const std = @import("std");

// LZSS Parameters optimized for text
const WINDOW_SIZE: usize = 4096;
const WINDOW_MASK: usize = WINDOW_SIZE - 1;
const MIN_MATCH_LEN: usize = 3;
const MAX_MATCH_LEN: usize = 18;
const HASH_SIZE: usize = 4096;
const HASH_MASK: usize = HASH_SIZE - 1;

// Memory layout - 4MB heap for large documents
const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4MB
var heap: [HEAP_SIZE]u8 align(16) = undefined;
var heap_offset: usize = 0;

// Hash chain for O(1) match finding
var hash_head: [HASH_SIZE]i32 = [_]i32{-1} ** HASH_SIZE;
var hash_prev: [WINDOW_SIZE]i32 = [_]i32{-1} ** WINDOW_SIZE;

// Base64URL alphabet (comptime optimized)
const base64url_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Reverse lookup table for base64url decoding (comptime generated)
const base64url_decode_table: [256]u8 = blk: {
    var table: [256]u8 = [_]u8{255} ** 256;
    for (base64url_alphabet, 0..) |c, i| {
        table[c] = @intCast(i);
    }
    break :blk table;
};

// Inline allocation for speed
inline fn allocInline(size: usize) ?[*]u8 {
    const aligned_size = (size + 7) & ~@as(usize, 7); // 8-byte alignment
    if (heap_offset + aligned_size > HEAP_SIZE) return null;
    const ptr = heap[heap_offset..].ptr;
    heap_offset += aligned_size;
    return ptr;
}

export fn alloc(size: usize) ?[*]u8 {
    return allocInline(size);
}

export fn free(ptr: [*]u8, size: usize) void {
    _ = ptr;
    _ = size;
}

export fn reset_heap() void {
    heap_offset = 0;
}

// Fast hash function for 3-byte sequences
inline fn hash3(data: []const u8, pos: usize) usize {
    if (pos + 2 >= data.len) return 0;
    const h = (@as(usize, data[pos]) << 10) ^
        (@as(usize, data[pos + 1]) << 5) ^
        @as(usize, data[pos + 2]);
    return h & HASH_MASK;
}

// Reset hash chains
inline fn resetHashChains() void {
    @memset(&hash_head, -1);
    @memset(&hash_prev, -1);
}

// LZSS Compression with hash chain optimization
export fn compress(input_ptr: [*]const u8, input_len: usize) u64 {
    if (input_len == 0) return 0;

    const input = input_ptr[0..input_len];

    // Allocate output buffer
    const max_output = input_len + (input_len >> 3) + 16;
    const output_ptr = allocInline(max_output) orelse return 0;
    const output = output_ptr[0..max_output];

    resetHashChains();

    var out_pos: usize = 0;
    var in_pos: usize = 0;
    var bit_buffer: u32 = 0;
    var bit_count: u5 = 0;

    while (in_pos < input_len) {
        var best_offset: usize = 0;
        var best_len: usize = 0;

        // Only search if we have enough bytes for minimum match
        if (in_pos + MIN_MATCH_LEN <= input_len) {
            const h = hash3(input, in_pos);
            var chain_pos = hash_head[h];
            const max_match = @min(MAX_MATCH_LEN, input_len - in_pos);
            var chain_limit: usize = 128; // Limit chain traversal

            // Walk the hash chain
            while (chain_pos >= 0 and chain_limit > 0) : (chain_limit -= 1) {
                const pos: usize = @intCast(chain_pos);
                const dist = in_pos - pos;

                if (dist > WINDOW_SIZE) break;

                // Quick check first and last bytes before full compare
                if (input[pos] == input[in_pos] and
                    input[pos + best_len] == input[in_pos + best_len])
                {
                    var match_len: usize = 0;
                    while (match_len < max_match and
                        input[pos + match_len] == input[in_pos + match_len])
                    {
                        match_len += 1;
                    }

                    if (match_len > best_len) {
                        best_len = match_len;
                        best_offset = dist;
                        if (best_len >= MAX_MATCH_LEN) break;
                    }
                }

                chain_pos = hash_prev[pos & WINDOW_MASK];
            }

            // Update hash chain
            hash_prev[in_pos & WINDOW_MASK] = hash_head[h];
            hash_head[h] = @intCast(in_pos);
        }

        // Write output
        if (best_len >= MIN_MATCH_LEN) {
            // Match: 1 + 12-bit offset + 4-bit length
            const bits: u32 = 1 |
                (@as(u32, @truncate(best_offset - 1)) << 1) |
                (@as(u32, @truncate(best_len - MIN_MATCH_LEN)) << 13);

            bit_buffer |= bits << bit_count;
            bit_count += 17;

            // Flush complete bytes
            while (bit_count >= 8) {
                if (out_pos < max_output) {
                    output[out_pos] = @truncate(bit_buffer);
                    out_pos += 1;
                }
                bit_buffer >>= 8;
                bit_count -= 8;
            }

            // Update hash for skipped positions
            var skip: usize = 1;
            while (skip < best_len and in_pos + skip + 2 < input_len) : (skip += 1) {
                const skip_h = hash3(input, in_pos + skip);
                hash_prev[(in_pos + skip) & WINDOW_MASK] = hash_head[skip_h];
                hash_head[skip_h] = @intCast(in_pos + skip);
            }

            in_pos += best_len;
        } else {
            // Literal: 0 + 8-bit byte
            const bits: u32 = @as(u32, input[in_pos]) << 1;
            bit_buffer |= bits << bit_count;
            bit_count += 9;

            while (bit_count >= 8) {
                if (out_pos < max_output) {
                    output[out_pos] = @truncate(bit_buffer);
                    out_pos += 1;
                }
                bit_buffer >>= 8;
                bit_count -= 8;
            }

            in_pos += 1;
        }
    }

    // Flush remaining bits
    if (bit_count > 0 and out_pos < max_output) {
        output[out_pos] = @truncate(bit_buffer);
        out_pos += 1;
    }

    return (@as(u64, @intFromPtr(output_ptr)) << 32) | @as(u64, out_pos);
}

// Optimized LZSS Decompression
export fn decompress(input_ptr: [*]const u8, input_len: usize) u64 {
    if (input_len == 0) return 0;

    const input = input_ptr[0..input_len];
    const max_output = input_len * 12;
    const output_ptr = allocInline(max_output) orelse return 0;
    const output = output_ptr[0..max_output];

    var out_pos: usize = 0;
    var in_pos: usize = 0;
    var bit_buffer: u32 = 0;
    var bit_count: u5 = 0;

    // Preload buffer
    while (bit_count < 24 and in_pos < input_len) {
        bit_buffer |= @as(u32, input[in_pos]) << bit_count;
        bit_count += 8;
        in_pos += 1;
    }

    while (bit_count > 0 or in_pos < input_len) {
        // Ensure we have enough bits
        while (bit_count < 17 and in_pos < input_len) {
            bit_buffer |= @as(u32, input[in_pos]) << bit_count;
            bit_count += 8;
            in_pos += 1;
        }

        if (bit_count == 0) break;

        const flag = bit_buffer & 1;
        bit_buffer >>= 1;
        bit_count -= 1;

        if (flag == 0) {
            // Literal
            if (bit_count < 8) {
                if (in_pos >= input_len) break;
                bit_buffer |= @as(u32, input[in_pos]) << bit_count;
                bit_count += 8;
                in_pos += 1;
            }

            if (out_pos < max_output) {
                output[out_pos] = @truncate(bit_buffer);
                out_pos += 1;
            }
            bit_buffer >>= 8;
            bit_count -= 8;
        } else {
            // Match
            if (bit_count < 16) {
                while (bit_count < 16 and in_pos < input_len) {
                    bit_buffer |= @as(u32, input[in_pos]) << bit_count;
                    bit_count += 8;
                    in_pos += 1;
                }
            }

            const offset = (bit_buffer & 0xFFF) + 1;
            bit_buffer >>= 12;
            const length = (bit_buffer & 0xF) + MIN_MATCH_LEN;
            bit_buffer >>= 4;
            bit_count -= 16;

            if (out_pos < offset) break;

            // Unrolled copy for common cases
            const src_start = out_pos - offset;
            var i: usize = 0;
            while (i < length and out_pos < max_output) : (i += 1) {
                output[out_pos] = output[src_start + i];
                out_pos += 1;
            }
        }
    }

    return (@as(u64, @intFromPtr(output_ptr)) << 32) | @as(u64, out_pos);
}

// Optimized Base64URL Encode - process 3 bytes at a time
export fn base64url_encode(input_ptr: [*]const u8, input_len: usize) u64 {
    if (input_len == 0) return 0;

    const input = input_ptr[0..input_len];
    const output_len = ((input_len * 4) + 2) / 3;
    const output_ptr = allocInline(output_len) orelse return 0;
    const output = output_ptr[0..output_len];

    var out_pos: usize = 0;
    var i: usize = 0;

    // Process 3 bytes at a time (main loop)
    const chunks = input_len / 3;
    var chunk: usize = 0;
    while (chunk < chunks) : (chunk += 1) {
        const idx = chunk * 3;
        const b0 = input[idx];
        const b1 = input[idx + 1];
        const b2 = input[idx + 2];

        output[out_pos] = base64url_alphabet[b0 >> 2];
        output[out_pos + 1] = base64url_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        output[out_pos + 2] = base64url_alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)];
        output[out_pos + 3] = base64url_alphabet[b2 & 0x3f];
        out_pos += 4;
    }

    // Handle remaining bytes
    i = chunks * 3;
    if (i < input_len) {
        const b0 = input[i];
        output[out_pos] = base64url_alphabet[b0 >> 2];
        out_pos += 1;

        if (i + 1 < input_len) {
            const b1 = input[i + 1];
            output[out_pos] = base64url_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
            output[out_pos + 1] = base64url_alphabet[(b1 & 0x0f) << 2];
            out_pos += 2;
        } else {
            output[out_pos] = base64url_alphabet[(b0 & 0x03) << 4];
            out_pos += 1;
        }
    }

    return (@as(u64, @intFromPtr(output_ptr)) << 32) | @as(u64, out_pos);
}

// Optimized Base64URL Decode - process 4 bytes at a time
export fn base64url_decode(input_ptr: [*]const u8, input_len: usize) u64 {
    if (input_len == 0) return 0;

    const input = input_ptr[0..input_len];
    const output_len = (input_len * 3) / 4 + 1;
    const output_ptr = allocInline(output_len) orelse return 0;
    const output = output_ptr[0..output_len];

    var out_pos: usize = 0;
    var i: usize = 0;

    // Process 4 bytes at a time
    while (i + 4 <= input_len) {
        const c0 = base64url_decode_table[input[i]];
        const c1 = base64url_decode_table[input[i + 1]];
        const c2 = base64url_decode_table[input[i + 2]];
        const c3 = base64url_decode_table[input[i + 3]];

        if (c0 == 255 or c1 == 255) break;

        output[out_pos] = (c0 << 2) | (c1 >> 4);
        out_pos += 1;

        if (c2 != 255) {
            output[out_pos] = ((c1 & 0x0f) << 4) | (c2 >> 2);
            out_pos += 1;

            if (c3 != 255) {
                output[out_pos] = ((c2 & 0x03) << 6) | c3;
                out_pos += 1;
            }
        }

        i += 4;
    }

    // Handle remaining bytes
    if (i < input_len) {
        const c0 = base64url_decode_table[input[i]];
        if (c0 == 255) {
            return (@as(u64, @intFromPtr(output_ptr)) << 32) | @as(u64, out_pos);
        }

        if (i + 1 < input_len) {
            const c1 = base64url_decode_table[input[i + 1]];
            if (c1 != 255) {
                output[out_pos] = (c0 << 2) | (c1 >> 4);
                out_pos += 1;

                if (i + 2 < input_len) {
                    const c2 = base64url_decode_table[input[i + 2]];
                    if (c2 != 255) {
                        output[out_pos] = ((c1 & 0x0f) << 4) | (c2 >> 2);
                        out_pos += 1;
                    }
                }
            }
        }
    }

    return (@as(u64, @intFromPtr(output_ptr)) << 32) | @as(u64, out_pos);
}

// Helper exports
export fn get_ptr(result: u64) usize {
    return @truncate(result >> 32);
}

export fn get_len(result: u64) usize {
    return @truncate(result & 0xFFFFFFFF);
}

// ============================================================================
// AES-256 ENCRYPTION (CTR Mode)
// ============================================================================

const AES_BLOCK_SIZE: usize = 16;
const AES_KEY_SIZE: usize = 32; // 256 bits
const AES_ROUNDS: usize = 14;

// AES S-box (comptime generated)
const sbox: [256]u8 = blk: {
    @setEvalBranchQuota(5000);
    var s: [256]u8 = undefined;
    var p: u8 = 1;
    var q: u8 = 1;
    s[0] = 0x63;
    while (true) {
        p = p ^ (p << 1) ^ (if (p & 0x80 != 0) @as(u8, 0x1B) else @as(u8, 0));
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if (q & 0x80 != 0) @as(u8, 0x09) else @as(u8, 0);
        const xformed = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
        s[p] = xformed ^ 0x63;
        if (p == 1) break;
    }
    break :blk s;
};

// Simple comptime-friendly rotate left for u8
inline fn rotl8(x: u8, r: u3) u8 {
    return (x << r) | (x >> @truncate(8 - @as(u4, r)));
}

// Round constants
const rcon: [11]u8 = .{ 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

// Key schedule
fn aesKeyExpansion(key: []const u8, round_keys: *[240]u8) void {
    var i: usize = 0;
    // Copy original key
    while (i < AES_KEY_SIZE) : (i += 1) {
        round_keys[i] = key[i];
    }

    var rcon_idx: usize = 1;
    while (i < 240) {
        var temp: [4]u8 = undefined;
        for (0..4) |j| temp[j] = round_keys[i - 4 + j];

        if (i % AES_KEY_SIZE == 0) {
            // RotWord + SubWord + Rcon
            const t = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[rcon_idx];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
            rcon_idx += 1;
        } else if (i % AES_KEY_SIZE == 16) {
            // SubWord only
            for (0..4) |j| temp[j] = sbox[temp[j]];
        }

        for (0..4) |j| {
            round_keys[i + j] = round_keys[i - AES_KEY_SIZE + j] ^ temp[j];
        }
        i += 4;
    }
}

// GF(2^8) multiplication
inline fn gmul(a: u8, b: u8) u8 {
    var result: u8 = 0;
    var aa = a;
    var bb = b;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        if (bb & 1 != 0) result ^= aa;
        const hi_bit = aa & 0x80;
        aa <<= 1;
        if (hi_bit != 0) aa ^= 0x1B;
        bb >>= 1;
    }
    return result;
}

// AES encrypt single block
fn aesEncryptBlock(input: []const u8, output: []u8, round_keys: []const u8) void {
    var state: [16]u8 = undefined;
    for (0..16) |i| state[i] = input[i] ^ round_keys[i];

    var round: usize = 1;
    while (round < AES_ROUNDS) : (round += 1) {
        // SubBytes
        for (0..16) |i| state[i] = sbox[state[i]];

        // ShiftRows
        const t1 = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = t1;

        const t2 = state[2];
        const t6 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = t2;
        state[14] = t6;

        const t3 = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = t3;

        // MixColumns
        var col: usize = 0;
        while (col < 4) : (col += 1) {
            const c = col * 4;
            const a0 = state[c];
            const a1 = state[c + 1];
            const a2 = state[c + 2];
            const a3 = state[c + 3];
            state[c] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
            state[c + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
            state[c + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
            state[c + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        }

        // AddRoundKey
        const rk = round * 16;
        for (0..16) |i| state[i] ^= round_keys[rk + i];
    }

    // Final round (no MixColumns)
    for (0..16) |i| state[i] = sbox[state[i]];

    const t1 = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t1;

    const t2 = state[2];
    const t6 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t2;
    state[14] = t6;

    const t3 = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t3;

    const rk = AES_ROUNDS * 16;
    for (0..16) |i| output[i] = state[i] ^ round_keys[rk + i];
}

// Simple key derivation (hash password multiple times)
fn deriveKey(password: []const u8, salt: []const u8, key: *[32]u8) void {
    var state: [32]u8 = undefined;
    // Initialize with salt
    for (0..32) |i| {
        state[i] = if (i < salt.len) salt[i] else @as(u8, @truncate(i));
    }

    // Mix in password multiple rounds
    var round: usize = 0;
    while (round < 1000) : (round += 1) {
        for (password, 0..) |p, i| {
            const idx = (i + round) % 32;
            state[idx] ^= p;
            state[idx] = sbox[state[idx]];
            state[(idx + 1) % 32] ^= state[idx];
        }
        // Diffusion (use temp buffer to avoid in-place corruption)
        var tmp: [32]u8 = undefined;
        for (0..32) |i| {
            tmp[i] = state[i] ^ state[(i + 13) % 32] ^ state[(i + 23) % 32];
        }
        state = tmp;
    }
    key.* = state;
}

// AES-256-CTR encrypt/decrypt
export fn aes_ctr_encrypt(data_ptr: [*]const u8, data_len: usize, key_ptr: [*]const u8, key_len: usize, nonce_ptr: [*]const u8) u64 {
    if (data_len == 0) return 0;

    const data = data_ptr[0..data_len];
    const password = key_ptr[0..key_len];
    const nonce = nonce_ptr[0..12];

    // Allocate output: 12 bytes nonce + ciphertext
    const output_len = 12 + data_len;
    const output_ptr = allocInline(output_len) orelse return 0;
    const output = output_ptr[0..output_len];

    // Copy nonce to output
    for (0..12) |i| output[i] = nonce[i];

    // Derive key from password
    var key: [32]u8 = undefined;
    deriveKey(password, nonce, &key);

    // Expand key
    var round_keys: [240]u8 = undefined;
    aesKeyExpansion(&key, &round_keys);

    // CTR mode encryption
    var counter: [16]u8 = undefined;
    for (0..12) |i| counter[i] = nonce[i];
    counter[12] = 0;
    counter[13] = 0;
    counter[14] = 0;
    counter[15] = 0;

    var keystream: [16]u8 = undefined;
    var pos: usize = 0;

    while (pos < data_len) {
        aesEncryptBlock(&counter, &keystream, &round_keys);

        // XOR with data
        var i: usize = 0;
        while (i < 16 and pos + i < data_len) : (i += 1) {
            output[12 + pos + i] = data[pos + i] ^ keystream[i];
        }
        pos += 16;

        // Increment counter
        var j: usize = 15;
        while (j >= 12) : (j -= 1) {
            counter[j] +%= 1;
            if (counter[j] != 0) break;
        }
    }

    return (@as(u64, @intFromPtr(output_ptr)) << 32) | @as(u64, output_len);
}

// AES-256-CTR decrypt (same as encrypt for CTR mode, but reads nonce from input)
export fn aes_ctr_decrypt(data_ptr: [*]const u8, data_len: usize, key_ptr: [*]const u8, key_len: usize) u64 {
    if (data_len <= 12) return 0;

    const data = data_ptr[0..data_len];
    const password = key_ptr[0..key_len];
    const nonce = data[0..12];
    const ciphertext = data[12..];

    // Allocate output
    const output_len = ciphertext.len;
    const output_ptr = allocInline(output_len) orelse return 0;
    const output = output_ptr[0..output_len];

    // Derive key from password
    var key: [32]u8 = undefined;
    deriveKey(password, nonce, &key);

    // Expand key
    var round_keys: [240]u8 = undefined;
    aesKeyExpansion(&key, &round_keys);

    // CTR mode decryption
    var counter: [16]u8 = undefined;
    for (0..12) |i| counter[i] = nonce[i];
    counter[12] = 0;
    counter[13] = 0;
    counter[14] = 0;
    counter[15] = 0;

    var keystream: [16]u8 = undefined;
    var pos: usize = 0;

    while (pos < output_len) {
        aesEncryptBlock(&counter, &keystream, &round_keys);

        var i: usize = 0;
        while (i < 16 and pos + i < output_len) : (i += 1) {
            output[pos + i] = ciphertext[pos + i] ^ keystream[i];
        }
        pos += 16;

        var j: usize = 15;
        while (j >= 12) : (j -= 1) {
            counter[j] +%= 1;
            if (counter[j] != 0) break;
        }
    }

    return (@as(u64, @intFromPtr(output_ptr)) << 32) | @as(u64, output_len);
}

// Generate random nonce using simple PRNG seeded with input
export fn generate_nonce(seed_ptr: [*]const u8, seed_len: usize) u64 {
    const output_ptr = allocInline(12) orelse return 0;
    const output = output_ptr[0..12];

    var state: u64 = 0x853c49e6748fea9b;
    const seed = seed_ptr[0..seed_len];
    for (seed) |b| {
        state ^= b;
        state *%= 0x2545F4914F6CDD1D;
    }

    for (0..12) |i| {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        output[i] = @truncate(state *% 0x2545F4914F6CDD1D >> 56);
    }

    return (@as(u64, @intFromPtr(output_ptr)) << 32) | 12;
}

// ============================================================================
// QR CODE GENERATION
// ============================================================================

const QR_MAX_VERSION = 10; // Support up to version 10 (57x57)
const QR_EC_LEVEL_L = 0; // ~7% recovery

// QR version capacities (bytes, L level)
const qr_capacity = [_]usize{ 0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271 };

// Error correction codewords per block
const qr_ec_codewords = [_]usize{ 0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18 };

// Number of blocks
const qr_num_blocks = [_]usize{ 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4 };

// QR code module buffer (max 57x57 = 3249 bits needed, use bytes)
var qr_modules: [60 * 60]u8 = undefined;
var qr_size: usize = 0;

// Get QR size for version
inline fn qrSize(version: usize) usize {
    return 17 + version * 4;
}

// Set module
inline fn setModule(x: usize, y: usize, value: u8) void {
    if (x < qr_size and y < qr_size) {
        qr_modules[y * qr_size + x] = value;
    }
}

// Get module
inline fn getModule(x: usize, y: usize) u8 {
    if (x < qr_size and y < qr_size) {
        return qr_modules[y * qr_size + x];
    }
    return 0;
}

// Draw finder pattern
fn drawFinder(cx: usize, cy: usize) void {
    var dy: i32 = -3;
    while (dy <= 3) : (dy += 1) {
        var dx: i32 = -3;
        while (dx <= 3) : (dx += 1) {
            const x = @as(usize, @intCast(@as(i32, @intCast(cx)) + dx));
            const y = @as(usize, @intCast(@as(i32, @intCast(cy)) + dy));
            const dist = @max(@abs(dx), @abs(dy));
            setModule(x, y, if (dist != 2) 1 else 0);
        }
    }
}

// Draw alignment pattern
fn drawAlignment(cx: usize, cy: usize) void {
    var dy: i32 = -2;
    while (dy <= 2) : (dy += 1) {
        var dx: i32 = -2;
        while (dx <= 2) : (dx += 1) {
            const x = @as(usize, @intCast(@as(i32, @intCast(cx)) + dx));
            const y = @as(usize, @intCast(@as(i32, @intCast(cy)) + dy));
            const dist = @max(@abs(dx), @abs(dy));
            setModule(x, y, if (dist != 1) 1 else 0);
        }
    }
}

// Alignment pattern positions (full set per version)
const alignment_pos = [_][]const usize{
    &.{},                       // v1 - none
    &.{ 6, 18 },                // v2
    &.{ 6, 22 },                // v3
    &.{ 6, 26 },                // v4
    &.{ 6, 30 },                // v5
    &.{ 6, 34 },                // v6
    &.{ 6, 22, 38 },            // v7
    &.{ 6, 24, 42 },            // v8
    &.{ 6, 26, 46 },            // v9
    &.{ 6, 28, 50 },            // v10
};

// Draw function patterns
fn drawFunctionPatterns(version: usize) void {
    // Finder patterns
    drawFinder(3, 3);
    drawFinder(qr_size - 4, 3);
    drawFinder(3, qr_size - 4);

    // Timing patterns
    for (8..qr_size - 8) |i| {
        const v: u8 = @truncate(i & 1 ^ 1);
        setModule(i, 6, v);
        setModule(6, i, v);
    }

    // Alignment patterns (version >= 2)
    if (version >= 2) {
        const positions = alignment_pos[version];
        for (positions) |py| {
            for (positions) |px| {
                // Skip if overlapping with finder patterns
                if (px <= 8 and py <= 8) continue;
                if (px >= qr_size - 8 and py <= 8) continue;
                if (px <= 8 and py >= qr_size - 8) continue;
                drawAlignment(px, py);
            }
        }
    }

    // Dark module
    setModule(8, qr_size - 8, 1);
}

// Reserve format info areas
fn reserveFormatAreas() void {
    // Around top-left finder
    for (0..9) |i| {
        setModule(i, 8, 2);
        setModule(8, i, 2);
    }
    // Around top-right finder
    for (qr_size - 8..qr_size) |i| {
        setModule(i, 8, 2);
    }
    // Around bottom-left finder
    for (qr_size - 7..qr_size) |i| {
        setModule(8, i, 2);
    }
}

// Check if position is data area
fn isDataArea(x: usize, y: usize) bool {
    // Skip timing patterns
    if (x == 6 or y == 6) return false;
    // Skip finder patterns
    if (x <= 8 and y <= 8) return false;
    if (x >= qr_size - 8 and y <= 8) return false;
    if (x <= 8 and y >= qr_size - 8) return false;
    // Skip format areas
    if (getModule(x, y) == 2) return false;
    return true;
}

// GF(256) operations for Reed-Solomon
const gf_exp: [512]u8 = blk: {
    var exp: [512]u8 = undefined;
    var x: u16 = 1;
    for (0..256) |i| {
        exp[i] = @truncate(x);
        x <<= 1;
        if (x >= 256) x ^= 0x11D;
    }
    for (256..512) |i| exp[i] = exp[i - 256];
    break :blk exp;
};

const gf_log: [256]u8 = blk: {
    var log: [256]u8 = undefined;
    log[0] = 0;
    var x: u16 = 1;
    for (0..255) |i| {
        log[@as(usize, @as(u8, @truncate(x)))] = @truncate(i);
        x <<= 1;
        if (x >= 256) x ^= 0x11D;
    }
    break :blk log;
};

fn gfMul(a: u8, b: u8) u8 {
    if (a == 0 or b == 0) return 0;
    return gf_exp[@as(usize, gf_log[a]) + @as(usize, gf_log[b])];
}

// Reed-Solomon error correction
fn rsEncode(data: []const u8, ec_len: usize, ec_out: []u8) void {
    // Generator polynomial coefficients (precomputed for common EC lengths)
    var gen: [32]u8 = undefined;
    gen[0] = 1;
    var gen_len: usize = 1;

    for (0..ec_len) |i| {
        var new_gen: [32]u8 = [_]u8{0} ** 32;
        const factor = gf_exp[i];
        for (0..gen_len) |j| {
            new_gen[j + 1] ^= gen[j];
            new_gen[j] ^= gfMul(gen[j], factor);
        }
        gen_len += 1;
        for (0..gen_len) |j| gen[j] = new_gen[j];
    }

    // Division
    var remainder: [32]u8 = [_]u8{0} ** 32;
    for (data) |b| {
        const factor = remainder[0] ^ b;
        for (0..ec_len - 1) |j| remainder[j] = remainder[j + 1];
        remainder[ec_len - 1] = 0;
        for (0..ec_len) |j| remainder[j] ^= gfMul(gen[ec_len - 1 - j], factor);
    }

    for (0..ec_len) |i| ec_out[i] = remainder[i];
}

// Place data bits in QR code
fn placeData(data: []const u8, data_bits: usize) void {
    var bit_idx: usize = 0;
    var x: usize = qr_size - 1;
    var going_up = true;

    while (x > 0) {
        if (x == 6) x -= 1; // Skip timing pattern column

        var y: usize = if (going_up) qr_size - 1 else 0;
        while (true) {
            for (0..2) |i| {
                const col = x - i;
                if (isDataArea(col, y) and getModule(col, y) != 2) {
                    const bit: u8 = if (bit_idx < data_bits)
                        @truncate((data[bit_idx / 8] >> @truncate(7 - (bit_idx % 8))) & 1)
                    else
                        0;
                    setModule(col, y, bit);
                    bit_idx += 1;
                }
            }

            if (going_up) {
                if (y == 0) break;
                y -= 1;
            } else {
                y += 1;
                if (y >= qr_size) break;
            }
        }

        going_up = !going_up;
        if (x < 2) break;
        x -= 2;
    }
}

// Apply mask pattern 0: (row + col) % 2 == 0
fn applyMask() void {
    for (0..qr_size) |y| {
        for (0..qr_size) |x| {
            if (isDataArea(x, y)) {
                if ((x + y) % 2 == 0) {
                    const v = getModule(x, y);
                    setModule(x, y, v ^ 1);
                }
            }
        }
    }
}

// Write format info
fn writeFormatInfo() void {
    // Format info for EC level L, mask 0
    const format_bits: u15 = 0x77C4; // Pre-calculated

    // Write around top-left
    for (0..6) |i| {
        const bit: u8 = @truncate((format_bits >> @truncate(i)) & 1);
        setModule(i, 8, bit);
    }
    setModule(7, 8, @truncate((format_bits >> 6) & 1));
    setModule(8, 8, @truncate((format_bits >> 7) & 1));
    setModule(8, 7, @truncate((format_bits >> 8) & 1));
    for (0..6) |i| {
        const bit: u8 = @truncate((format_bits >> @truncate(9 + i)) & 1);
        setModule(8, 5 - i, bit);
    }

    // Write around other finders
    for (0..7) |i| {
        const bit: u8 = @truncate((format_bits >> @truncate(i)) & 1);
        setModule(8, qr_size - 1 - i, bit);
    }
    for (0..8) |i| {
        const bit: u8 = @truncate((format_bits >> @truncate(7 + i)) & 1);
        setModule(qr_size - 8 + i, 8, bit);
    }
}

// Generate QR code - returns size in upper 32 bits, data ptr in lower
export fn generate_qr(data_ptr: [*]const u8, data_len: usize) u64 {
    if (data_len == 0) return 0;

    const data = data_ptr[0..data_len];

    // Find smallest version that fits
    var version: usize = 1;
    while (version <= QR_MAX_VERSION) : (version += 1) {
        if (qr_capacity[version] >= data_len + 3) break; // +3 for mode and length
    }
    if (version > QR_MAX_VERSION) return 0;

    qr_size = qrSize(version);

    // Clear modules
    @memset(&qr_modules, 0);

    // Draw function patterns
    drawFunctionPatterns(version);
    reserveFormatAreas();

    // Encode data in byte mode
    const total_codewords = qr_capacity[version] + qr_ec_codewords[version] * qr_num_blocks[version];
    const data_codewords = qr_capacity[version];
    const ec_per_block = qr_ec_codewords[version];

    var codewords: [300]u8 = [_]u8{0} ** 300;
    var cw_idx: usize = 0;

    // Mode indicator (0100 = byte) + length (8 bits for v1-9, 16 for v10+)
    if (version < 10) {
        codewords[0] = 0x40 | @as(u8, @truncate(data_len >> 4));
        codewords[1] = @as(u8, @truncate(data_len << 4));
        cw_idx = 1;
        const bit_offset: u3 = 4;

        for (data) |b| {
            codewords[cw_idx] |= b >> bit_offset;
            cw_idx += 1;
            codewords[cw_idx] = @as(u8, @truncate(@as(u16, b) << @truncate(8 - @as(u4, bit_offset))));
        }
        cw_idx += 1;
    } else {
        codewords[0] = 0x40;
        codewords[1] = @truncate(data_len >> 8);
        codewords[2] = @truncate(data_len);
        for (data, 0..) |b, i| codewords[3 + i] = b;
        cw_idx = 3 + data_len;
    }

    // Pad to data capacity
    while (cw_idx < data_codewords) : (cw_idx += 1) {
        codewords[cw_idx] = if (cw_idx % 2 == 0) 0xEC else 0x11;
    }

    // Generate error correction
    var ec_data: [300]u8 = undefined;
    const blocks = qr_num_blocks[version];
    const block_size = data_codewords / blocks;

    for (0..blocks) |b| {
        rsEncode(codewords[b * block_size .. (b + 1) * block_size], ec_per_block, ec_data[b * ec_per_block .. (b + 1) * ec_per_block]);
    }

    // Interleave data and EC
    var final_data: [400]u8 = undefined;
    var final_idx: usize = 0;

    // Interleave data blocks
    for (0..block_size) |i| {
        for (0..blocks) |b| {
            final_data[final_idx] = codewords[b * block_size + i];
            final_idx += 1;
        }
    }

    // Interleave EC blocks
    for (0..ec_per_block) |i| {
        for (0..blocks) |b| {
            final_data[final_idx] = ec_data[b * ec_per_block + i];
            final_idx += 1;
        }
    }

    // Place data
    placeData(&final_data, total_codewords * 8);

    // Apply mask
    applyMask();

    // Write format info
    writeFormatInfo();

    // Copy to output buffer
    const output_size = qr_size * qr_size;
    const output_ptr = allocInline(output_size) orelse return 0;
    const output = output_ptr[0..output_size];

    for (0..qr_size) |y| {
        for (0..qr_size) |x| {
            output[y * qr_size + x] = getModule(x, y) & 1;
        }
    }

    // Return: size in upper 16 bits of upper 32, ptr conceptually separate
    return (@as(u64, @intFromPtr(output_ptr)) << 32) | (@as(u64, qr_size) << 16) | @as(u64, output_size);
}

// Get QR size from result
export fn get_qr_size(result: u64) usize {
    return @truncate((result >> 16) & 0xFFFF);
}

// ============================================================================
// HASH FUNCTION FOR SHARE CODES (xxHash-inspired)
// ============================================================================

const PRIME1: u64 = 0x9E3779B185EBCA87;
const PRIME2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME3: u64 = 0x165667B19E3779F9;
const PRIME4: u64 = 0x85EBCA77C2B2AE63;
const PRIME5: u64 = 0x27D4EB2F165667C5;

inline fn xxhRound(acc: u64, input: u64) u64 {
    var a = acc;
    a +%= input *% PRIME2;
    a = (a << 31) | (a >> 33);
    a *%= PRIME1;
    return a;
}

inline fn xxhAvalanche(h: u64) u64 {
    var hash = h;
    hash ^= hash >> 33;
    hash *%= PRIME2;
    hash ^= hash >> 29;
    hash *%= PRIME3;
    hash ^= hash >> 32;
    return hash;
}

// Generate 64-bit hash of data - returns 8-char base64url string
export fn hash_data(data_ptr: [*]const u8, data_len: usize) u64 {
    if (data_len == 0) return 0;

    const data = data_ptr[0..data_len];
    var h: u64 = PRIME5;

    // Process 8 bytes at a time
    var i: usize = 0;
    while (i + 8 <= data_len) : (i += 8) {
        const chunk = @as(u64, data[i]) |
            (@as(u64, data[i + 1]) << 8) |
            (@as(u64, data[i + 2]) << 16) |
            (@as(u64, data[i + 3]) << 24) |
            (@as(u64, data[i + 4]) << 32) |
            (@as(u64, data[i + 5]) << 40) |
            (@as(u64, data[i + 6]) << 48) |
            (@as(u64, data[i + 7]) << 56);
        h = xxhRound(h, chunk);
    }

    // Process remaining bytes
    while (i < data_len) : (i += 1) {
        h ^= @as(u64, data[i]) *% PRIME5;
        h = ((h << 11) | (h >> 53)) *% PRIME1;
    }

    h ^= data_len;
    h = xxhAvalanche(h);

    // Encode as 11-char base64url (66 bits, truncated to 64)
    const output_ptr = allocInline(11) orelse return 0;
    const output = output_ptr[0..11];

    var remaining = h;
    for (0..11) |j| {
        output[j] = base64url_alphabet[@as(usize, @truncate(remaining & 0x3F))];
        remaining >>= 6;
    }

    return (@as(u64, @intFromPtr(output_ptr)) << 32) | 11;
}

// Get heap usage info
export fn get_heap_used() usize {
    return heap_offset;
}

export fn get_heap_size() usize {
    return HEAP_SIZE;
}

// ============================================================================
// SESSION MANAGEMENT (12-hour expiry)
// ============================================================================

const SESSION_DURATION_SECS: u64 = 12 * 60 * 60; // 12 hours in seconds
const SESSION_ID_LEN: usize = 16;

// Session state
var session_id: [SESSION_ID_LEN]u8 = [_]u8{0} ** SESSION_ID_LEN;
var session_created_at: u64 = 0;
var session_active: bool = false;

// PRNG state for session ID generation
var prng_state: u64 = 0x853c49e6748fea9b;

fn prngNext() u64 {
    prng_state ^= prng_state >> 12;
    prng_state ^= prng_state << 25;
    prng_state ^= prng_state >> 27;
    return prng_state *% 0x2545F4914F6CDD1D;
}

// Create a new session - returns pointer to session ID
// current_time_secs: Unix timestamp in seconds from JS
export fn session_create(current_time_secs: u64, seed: u64) u64 {
    // Seed the PRNG with time and provided seed
    prng_state = current_time_secs ^ seed ^ 0x853c49e6748fea9b;
    
    // Generate session ID (base64url characters)
    for (0..SESSION_ID_LEN) |i| {
        const rand_val = prngNext();
        session_id[i] = base64url_alphabet[@as(usize, @truncate(rand_val & 0x3F))];
    }
    
    session_created_at = current_time_secs;
    session_active = true;
    
    return (@as(u64, @intFromPtr(&session_id)) << 32) | SESSION_ID_LEN;
}

// Validate session - returns 1 if valid, 0 if expired/invalid
// current_time_secs: Unix timestamp in seconds from JS
export fn session_validate(current_time_secs: u64) u8 {
    if (!session_active) return 0;
    
    const elapsed = current_time_secs -| session_created_at;
    if (elapsed >= SESSION_DURATION_SECS) {
        // Session expired - auto invalidate
        session_active = false;
        @memset(&session_id, 0);
        session_created_at = 0;
        return 0;
    }
    
    return 1;
}

// Get remaining session time in seconds (0 if expired/invalid)
export fn session_remaining(current_time_secs: u64) u64 {
    if (!session_active) return 0;
    
    const elapsed = current_time_secs -| session_created_at;
    if (elapsed >= SESSION_DURATION_SECS) {
        return 0;
    }
    
    return SESSION_DURATION_SECS - elapsed;
}

// Get session ID - returns pointer and length (0 if no active session)
export fn session_get_id() u64 {
    if (!session_active) return 0;
    return (@as(u64, @intFromPtr(&session_id)) << 32) | SESSION_ID_LEN;
}

// Manually invalidate/destroy session
export fn session_invalidate() void {
    session_active = false;
    @memset(&session_id, 0);
    session_created_at = 0;
}

// Refresh session (extend expiry from current time)
export fn session_refresh(current_time_secs: u64) u8 {
    if (!session_active) return 0;
    
    // Only refresh if session is still valid
    const elapsed = current_time_secs -| session_created_at;
    if (elapsed >= SESSION_DURATION_SECS) {
        session_active = false;
        @memset(&session_id, 0);
        session_created_at = 0;
        return 0;
    }
    
    // Extend session
    session_created_at = current_time_secs;
    return 1;
}

// Check if session is active (without time check)
export fn session_is_active() u8 {
    return if (session_active) 1 else 0;
}

// Get session creation timestamp
export fn session_get_created_at() u64 {
    return session_created_at;
}

// ============================================================================
// SYNTAX HIGHLIGHTING LEXER
// ============================================================================

// Token types (must match JS side)
const TokenType = enum(u8) {
    keyword = 1,
    string = 2,
    number = 3,
    comment = 4,
    operator = 5,
    punctuation = 6,
    function_name = 7,
    type_name = 8,
    variable = 9,
    tag = 10,
    attribute = 11,
    property = 12,
};

// Language types
const Language = enum(u8) {
    plain = 0,
    javascript = 1,
    json = 2,
    html = 3,
    css = 4,
    python = 5,
    markdown = 6,
    zig = 7,
};

// Token structure: 4 bytes start, 4 bytes length, 1 byte type = 9 bytes per token
const TOKEN_SIZE = 9;
const MAX_TOKENS = 50000;

// Keywords for different languages
const js_keywords = [_][]const u8{
    "async", "await", "break", "case", "catch", "class", "const", "continue",
    "debugger", "default", "delete", "do", "else", "export", "extends", "false",
    "finally", "for", "from", "function", "if", "import", "in", "instanceof",
    "let", "new", "null", "of", "return", "static", "super", "switch", "this",
    "throw", "true", "try", "typeof", "undefined", "var", "void", "while", "with", "yield",
};

const python_keywords = [_][]const u8{
    "False", "None", "True", "and", "as", "assert", "async", "await", "break",
    "class", "continue", "def", "del", "elif", "else", "except", "finally",
    "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
};

const zig_keywords = [_][]const u8{
    "addrspace", "align", "allowzero", "and", "anyframe", "anytype", "asm",
    "async", "await", "break", "callconv", "catch", "comptime", "const",
    "continue", "defer", "else", "enum", "errdefer", "error", "export",
    "extern", "false", "fn", "for", "if", "inline", "noalias", "nosuspend",
    "null", "opaque", "or", "orelse", "packed", "pub", "resume", "return",
    "struct", "suspend", "switch", "test", "threadlocal", "true", "try",
    "undefined", "union", "unreachable", "usingnamespace", "var", "volatile", "while",
};

const css_keywords = [_][]const u8{
    "important", "inherit", "initial", "unset", "none", "auto", "block",
    "inline", "flex", "grid", "absolute", "relative", "fixed", "sticky",
    "hidden", "visible", "solid", "dashed", "dotted", "transparent",
};

fn isKeyword(word: []const u8, lang: Language) bool {
    const keywords = switch (lang) {
        .javascript, .json => &js_keywords,
        .python => &python_keywords,
        .zig => &zig_keywords,
        .css => &css_keywords,
        else => return false,
    };
    for (keywords) |kw| {
        if (std.mem.eql(u8, word, kw)) return true;
    }
    return false;
}

fn isAlpha(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_' or c == '$';
}

fn isAlnum(c: u8) bool {
    return isAlpha(c) or (c >= '0' and c <= '9');
}

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

fn isHexDigit(c: u8) bool {
    return isDigit(c) or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn isWhitespace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

// Write token to output buffer
fn writeToken(output: []u8, idx: *usize, start: usize, length: usize, token_type: TokenType) void {
    if (idx.* + TOKEN_SIZE > output.len) return;

    // Write start position (4 bytes, little endian)
    output[idx.*] = @truncate(start);
    output[idx.* + 1] = @truncate(start >> 8);
    output[idx.* + 2] = @truncate(start >> 16);
    output[idx.* + 3] = @truncate(start >> 24);

    // Write length (4 bytes, little endian)
    output[idx.* + 4] = @truncate(length);
    output[idx.* + 5] = @truncate(length >> 8);
    output[idx.* + 6] = @truncate(length >> 16);
    output[idx.* + 7] = @truncate(length >> 24);

    // Write type (1 byte)
    output[idx.* + 8] = @intFromEnum(token_type);

    idx.* += TOKEN_SIZE;
}

// Tokenize JavaScript/TypeScript
fn tokenizeJS(input: []const u8, output: []u8) usize {
    var idx: usize = 0;
    var pos: usize = 0;

    while (pos < input.len and idx + TOKEN_SIZE <= output.len) {
        const c = input[pos];

        // Skip whitespace
        if (isWhitespace(c)) {
            pos += 1;
            continue;
        }

        // Single-line comment
        if (c == '/' and pos + 1 < input.len and input[pos + 1] == '/') {
            const start = pos;
            while (pos < input.len and input[pos] != '\n') pos += 1;
            writeToken(output, &idx, start, pos - start, .comment);
            continue;
        }

        // Multi-line comment
        if (c == '/' and pos + 1 < input.len and input[pos + 1] == '*') {
            const start = pos;
            pos += 2;
            while (pos + 1 < input.len and !(input[pos] == '*' and input[pos + 1] == '/')) pos += 1;
            pos += 2;
            writeToken(output, &idx, start, pos - start, .comment);
            continue;
        }

        // String (single, double, template)
        if (c == '"' or c == '\'' or c == '`') {
            const quote = c;
            const start = pos;
            pos += 1;
            while (pos < input.len) {
                if (input[pos] == '\\' and pos + 1 < input.len) {
                    pos += 2;
                } else if (input[pos] == quote) {
                    pos += 1;
                    break;
                } else if (quote != '`' and input[pos] == '\n') {
                    break;
                } else {
                    pos += 1;
                }
            }
            writeToken(output, &idx, start, pos - start, .string);
            continue;
        }

        // Number
        if (isDigit(c) or (c == '.' and pos + 1 < input.len and isDigit(input[pos + 1]))) {
            const start = pos;
            if (c == '0' and pos + 1 < input.len and (input[pos + 1] == 'x' or input[pos + 1] == 'X')) {
                pos += 2;
                while (pos < input.len and isHexDigit(input[pos])) pos += 1;
            } else {
                while (pos < input.len and (isDigit(input[pos]) or input[pos] == '.')) pos += 1;
                if (pos < input.len and (input[pos] == 'e' or input[pos] == 'E')) {
                    pos += 1;
                    if (pos < input.len and (input[pos] == '+' or input[pos] == '-')) pos += 1;
                    while (pos < input.len and isDigit(input[pos])) pos += 1;
                }
            }
            writeToken(output, &idx, start, pos - start, .number);
            continue;
        }

        // Identifier/keyword
        if (isAlpha(c)) {
            const start = pos;
            while (pos < input.len and isAlnum(input[pos])) pos += 1;
            const word = input[start..pos];

            if (isKeyword(word, .javascript)) {
                writeToken(output, &idx, start, pos - start, .keyword);
            } else if (pos < input.len and input[pos] == '(') {
                writeToken(output, &idx, start, pos - start, .function_name);
            } else if (word.len > 0 and word[0] >= 'A' and word[0] <= 'Z') {
                writeToken(output, &idx, start, pos - start, .type_name);
            }
            continue;
        }

        // Operators
        if (c == '+' or c == '-' or c == '*' or c == '/' or c == '=' or c == '<' or c == '>' or
            c == '!' or c == '&' or c == '|' or c == '^' or c == '%' or c == '~' or c == '?')
        {
            const start = pos;
            pos += 1;
            // Handle multi-char operators
            if (pos < input.len) {
                const next = input[pos];
                if ((c == '=' and (next == '=' or next == '>')) or
                    (c == '!' and next == '=') or
                    (c == '<' and (next == '=' or next == '<')) or
                    (c == '>' and (next == '=' or next == '>')) or
                    (c == '&' and next == '&') or
                    (c == '|' and next == '|') or
                    (c == '+' and next == '+') or
                    (c == '-' and next == '-') or
                    (c == '*' and next == '*') or
                    (c == '?' and next == '?'))
                {
                    pos += 1;
                    if (pos < input.len and input[pos] == '=') pos += 1;
                }
            }
            writeToken(output, &idx, start, pos - start, .operator);
            continue;
        }

        // Punctuation
        if (c == '(' or c == ')' or c == '[' or c == ']' or c == '{' or c == '}' or
            c == ',' or c == ';' or c == ':' or c == '.')
        {
            writeToken(output, &idx, pos, 1, .punctuation);
            pos += 1;
            continue;
        }

        pos += 1;
    }

    return idx;
}

// Tokenize HTML
fn tokenizeHTML(input: []const u8, output: []u8) usize {
    var idx: usize = 0;
    var pos: usize = 0;

    while (pos < input.len and idx + TOKEN_SIZE <= output.len) {
        const c = input[pos];

        // Comment
        if (c == '<' and pos + 3 < input.len and input[pos + 1] == '!' and input[pos + 2] == '-' and input[pos + 3] == '-') {
            const start = pos;
            pos += 4;
            while (pos + 2 < input.len and !(input[pos] == '-' and input[pos + 1] == '-' and input[pos + 2] == '>')) pos += 1;
            pos += 3;
            writeToken(output, &idx, start, pos - start, .comment);
            continue;
        }

        // Tag
        if (c == '<') {
            pos += 1;
            if (pos < input.len and input[pos] == '/') pos += 1;

            // Tag name
            const tag_start = pos;
            while (pos < input.len and isAlnum(input[pos])) pos += 1;
            if (pos > tag_start) {
                writeToken(output, &idx, tag_start, pos - tag_start, .tag);
            }

            // Attributes
            while (pos < input.len and input[pos] != '>') {
                if (isWhitespace(input[pos])) {
                    pos += 1;
                    continue;
                }

                // Attribute name
                if (isAlpha(input[pos])) {
                    const attr_start = pos;
                    while (pos < input.len and (isAlnum(input[pos]) or input[pos] == '-')) pos += 1;
                    writeToken(output, &idx, attr_start, pos - attr_start, .attribute);

                    // Skip =
                    while (pos < input.len and isWhitespace(input[pos])) pos += 1;
                    if (pos < input.len and input[pos] == '=') {
                        pos += 1;
                        while (pos < input.len and isWhitespace(input[pos])) pos += 1;

                        // Attribute value
                        if (pos < input.len and (input[pos] == '"' or input[pos] == '\'')) {
                            const quote = input[pos];
                            const val_start = pos;
                            pos += 1;
                            while (pos < input.len and input[pos] != quote) pos += 1;
                            pos += 1;
                            writeToken(output, &idx, val_start, pos - val_start, .string);
                        }
                    }
                    continue;
                }

                pos += 1;
            }
            if (pos < input.len) pos += 1; // Skip >
            continue;
        }

        pos += 1;
    }

    return idx;
}

// Tokenize CSS
fn tokenizeCSS(input: []const u8, output: []u8) usize {
    var idx: usize = 0;
    var pos: usize = 0;

    while (pos < input.len and idx + TOKEN_SIZE <= output.len) {
        const c = input[pos];

        if (isWhitespace(c)) {
            pos += 1;
            continue;
        }

        // Comment
        if (c == '/' and pos + 1 < input.len and input[pos + 1] == '*') {
            const start = pos;
            pos += 2;
            while (pos + 1 < input.len and !(input[pos] == '*' and input[pos + 1] == '/')) pos += 1;
            pos += 2;
            writeToken(output, &idx, start, pos - start, .comment);
            continue;
        }

        // String
        if (c == '"' or c == '\'') {
            const quote = c;
            const start = pos;
            pos += 1;
            while (pos < input.len and input[pos] != quote) {
                if (input[pos] == '\\' and pos + 1 < input.len) pos += 2 else pos += 1;
            }
            if (pos < input.len) pos += 1;
            writeToken(output, &idx, start, pos - start, .string);
            continue;
        }

        // Number with unit
        if (isDigit(c) or (c == '.' and pos + 1 < input.len and isDigit(input[pos + 1]))) {
            const start = pos;
            while (pos < input.len and (isDigit(input[pos]) or input[pos] == '.')) pos += 1;
            // Unit
            while (pos < input.len and isAlpha(input[pos])) pos += 1;
            writeToken(output, &idx, start, pos - start, .number);
            continue;
        }

        // Color
        if (c == '#') {
            const start = pos;
            pos += 1;
            while (pos < input.len and isHexDigit(input[pos])) pos += 1;
            writeToken(output, &idx, start, pos - start, .number);
            continue;
        }

        // Property or selector
        if (isAlpha(c) or c == '-' or c == '_') {
            const start = pos;
            while (pos < input.len and (isAlnum(input[pos]) or input[pos] == '-' or input[pos] == '_')) pos += 1;
            const word = input[start..pos];

            if (isKeyword(word, .css)) {
                writeToken(output, &idx, start, pos - start, .keyword);
            } else {
                writeToken(output, &idx, start, pos - start, .property);
            }
            continue;
        }

        // Punctuation
        if (c == '{' or c == '}' or c == ':' or c == ';' or c == ',' or c == '(' or c == ')') {
            writeToken(output, &idx, pos, 1, .punctuation);
            pos += 1;
            continue;
        }

        pos += 1;
    }

    return idx;
}

// Tokenize Python
fn tokenizePython(input: []const u8, output: []u8) usize {
    var idx: usize = 0;
    var pos: usize = 0;

    while (pos < input.len and idx + TOKEN_SIZE <= output.len) {
        const c = input[pos];

        if (isWhitespace(c)) {
            pos += 1;
            continue;
        }

        // Comment
        if (c == '#') {
            const start = pos;
            while (pos < input.len and input[pos] != '\n') pos += 1;
            writeToken(output, &idx, start, pos - start, .comment);
            continue;
        }

        // Triple-quoted string
        if ((c == '"' or c == '\'') and pos + 2 < input.len and input[pos + 1] == c and input[pos + 2] == c) {
            const quote = c;
            const start = pos;
            pos += 3;
            while (pos + 2 < input.len and !(input[pos] == quote and input[pos + 1] == quote and input[pos + 2] == quote)) pos += 1;
            pos += 3;
            writeToken(output, &idx, start, pos - start, .string);
            continue;
        }

        // String
        if (c == '"' or c == '\'') {
            const quote = c;
            const start = pos;
            pos += 1;
            while (pos < input.len and input[pos] != quote and input[pos] != '\n') {
                if (input[pos] == '\\' and pos + 1 < input.len) pos += 2 else pos += 1;
            }
            if (pos < input.len and input[pos] == quote) pos += 1;
            writeToken(output, &idx, start, pos - start, .string);
            continue;
        }

        // Number
        if (isDigit(c)) {
            const start = pos;
            if (c == '0' and pos + 1 < input.len) {
                const next = input[pos + 1];
                if (next == 'x' or next == 'X' or next == 'b' or next == 'B' or next == 'o' or next == 'O') {
                    pos += 2;
                    while (pos < input.len and (isHexDigit(input[pos]) or input[pos] == '_')) pos += 1;
                    writeToken(output, &idx, start, pos - start, .number);
                    continue;
                }
            }
            while (pos < input.len and (isDigit(input[pos]) or input[pos] == '.' or input[pos] == '_')) pos += 1;
            if (pos < input.len and (input[pos] == 'e' or input[pos] == 'E')) {
                pos += 1;
                if (pos < input.len and (input[pos] == '+' or input[pos] == '-')) pos += 1;
                while (pos < input.len and isDigit(input[pos])) pos += 1;
            }
            writeToken(output, &idx, start, pos - start, .number);
            continue;
        }

        // Identifier/keyword
        if (isAlpha(c)) {
            const start = pos;
            while (pos < input.len and isAlnum(input[pos])) pos += 1;
            const word = input[start..pos];

            if (isKeyword(word, .python)) {
                writeToken(output, &idx, start, pos - start, .keyword);
            } else if (pos < input.len and input[pos] == '(') {
                writeToken(output, &idx, start, pos - start, .function_name);
            } else if (word.len > 0 and word[0] >= 'A' and word[0] <= 'Z') {
                writeToken(output, &idx, start, pos - start, .type_name);
            }
            continue;
        }

        // Operators
        if (c == '+' or c == '-' or c == '*' or c == '/' or c == '=' or c == '<' or c == '>' or
            c == '!' or c == '&' or c == '|' or c == '^' or c == '%' or c == '~' or c == '@')
        {
            const start = pos;
            pos += 1;
            if (pos < input.len and (input[pos] == '=' or input[pos] == c)) pos += 1;
            writeToken(output, &idx, start, pos - start, .operator);
            continue;
        }

        // Punctuation
        if (c == '(' or c == ')' or c == '[' or c == ']' or c == '{' or c == '}' or
            c == ',' or c == ':' or c == '.')
        {
            writeToken(output, &idx, pos, 1, .punctuation);
            pos += 1;
            continue;
        }

        pos += 1;
    }

    return idx;
}

// Tokenize JSON
fn tokenizeJSON(input: []const u8, output: []u8) usize {
    var idx: usize = 0;
    var pos: usize = 0;

    while (pos < input.len and idx + TOKEN_SIZE <= output.len) {
        const c = input[pos];

        if (isWhitespace(c)) {
            pos += 1;
            continue;
        }

        // String (property or value)
        if (c == '"') {
            const start = pos;
            pos += 1;
            while (pos < input.len and input[pos] != '"') {
                if (input[pos] == '\\' and pos + 1 < input.len) pos += 2 else pos += 1;
            }
            if (pos < input.len) pos += 1;

            // Check if this is a property (followed by :)
            var peek = pos;
            while (peek < input.len and isWhitespace(input[peek])) peek += 1;
            if (peek < input.len and input[peek] == ':') {
                writeToken(output, &idx, start, pos - start, .property);
            } else {
                writeToken(output, &idx, start, pos - start, .string);
            }
            continue;
        }

        // Number
        if (isDigit(c) or c == '-') {
            const start = pos;
            if (c == '-') pos += 1;
            while (pos < input.len and isDigit(input[pos])) pos += 1;
            if (pos < input.len and input[pos] == '.') {
                pos += 1;
                while (pos < input.len and isDigit(input[pos])) pos += 1;
            }
            if (pos < input.len and (input[pos] == 'e' or input[pos] == 'E')) {
                pos += 1;
                if (pos < input.len and (input[pos] == '+' or input[pos] == '-')) pos += 1;
                while (pos < input.len and isDigit(input[pos])) pos += 1;
            }
            writeToken(output, &idx, start, pos - start, .number);
            continue;
        }

        // Keywords: true, false, null
        if (isAlpha(c)) {
            const start = pos;
            while (pos < input.len and isAlpha(input[pos])) pos += 1;
            writeToken(output, &idx, start, pos - start, .keyword);
            continue;
        }

        // Punctuation
        if (c == '{' or c == '}' or c == '[' or c == ']' or c == ':' or c == ',') {
            writeToken(output, &idx, pos, 1, .punctuation);
            pos += 1;
            continue;
        }

        pos += 1;
    }

    return idx;
}

// Tokenize Zig (proper keyword set + @builtin handling)
fn tokenizeZig(input: []const u8, output: []u8) usize {
    var idx: usize = 0;
    var pos: usize = 0;

    while (pos < input.len and idx + TOKEN_SIZE <= output.len) {
        const c = input[pos];

        if (isWhitespace(c)) { pos += 1; continue; }

        // Single-line comment
        if (c == '/' and pos + 1 < input.len and input[pos + 1] == '/') {
            const start = pos;
            while (pos < input.len and input[pos] != '\n') pos += 1;
            writeToken(output, &idx, start, pos - start, .comment);
            continue;
        }

        // String / char literal
        if (c == '"' or c == '\'') {
            const quote = c;
            const start = pos;
            pos += 1;
            while (pos < input.len) {
                if (input[pos] == '\\' and pos + 1 < input.len) { pos += 2; }
                else if (input[pos] == quote) { pos += 1; break; }
                else if (input[pos] == '\n') break
                else { pos += 1; }
            }
            writeToken(output, &idx, start, pos - start, .string);
            continue;
        }

        // Number
        if (isDigit(c) or (c == '.' and pos + 1 < input.len and isDigit(input[pos + 1]))) {
            const start = pos;
            if (c == '0' and pos + 1 < input.len and (input[pos + 1] == 'x' or input[pos + 1] == 'b' or input[pos + 1] == 'o')) {
                pos += 2;
                while (pos < input.len and (isHexDigit(input[pos]) or input[pos] == '_')) pos += 1;
            } else {
                while (pos < input.len and (isDigit(input[pos]) or input[pos] == '.' or input[pos] == '_')) pos += 1;
                if (pos < input.len and (input[pos] == 'e' or input[pos] == 'E')) {
                    pos += 1;
                    if (pos < input.len and (input[pos] == '+' or input[pos] == '-')) pos += 1;
                    while (pos < input.len and isDigit(input[pos])) pos += 1;
                }
            }
            writeToken(output, &idx, start, pos - start, .number);
            continue;
        }

        // @builtin calls
        if (c == '@' and pos + 1 < input.len and isAlpha(input[pos + 1])) {
            const start = pos;
            pos += 1;
            while (pos < input.len and isAlnum(input[pos])) pos += 1;
            writeToken(output, &idx, start, pos - start, .function_name);
            continue;
        }

        // Identifier/keyword
        if (isAlpha(c)) {
            const start = pos;
            while (pos < input.len and isAlnum(input[pos])) pos += 1;
            const word = input[start..pos];
            if (isKeyword(word, .zig)) {
                writeToken(output, &idx, start, pos - start, .keyword);
            } else if (pos < input.len and input[pos] == '(') {
                writeToken(output, &idx, start, pos - start, .function_name);
            } else if (word.len > 0 and word[0] >= 'A' and word[0] <= 'Z') {
                writeToken(output, &idx, start, pos - start, .type_name);
            }
            continue;
        }

        // Operators
        if (c == '+' or c == '-' or c == '*' or c == '/' or c == '=' or c == '<' or c == '>' or
            c == '!' or c == '&' or c == '|' or c == '^' or c == '%' or c == '~' or c == '?')
        {
            const start = pos;
            pos += 1;
            if (pos < input.len) {
                const next = input[pos];
                if ((c == '=' and next == '=') or (c == '!' and next == '=') or
                    (c == '<' and (next == '=' or next == '<')) or
                    (c == '>' and (next == '=' or next == '>')) or
                    (c == '+' and next == '+') or (c == '*' and next == '*'))
                { pos += 1; }
            }
            writeToken(output, &idx, start, pos - start, .operator);
            continue;
        }

        // Punctuation
        if (c == '(' or c == ')' or c == '[' or c == ']' or c == '{' or c == '}' or
            c == ',' or c == ';' or c == ':' or c == '.')
        {
            writeToken(output, &idx, pos, 1, .punctuation);
            pos += 1;
            continue;
        }

        pos += 1;
    }
    return idx;
}

// Tokenize Markdown (headings, bold, italic, code, links)
fn tokenizeMarkdown(input: []const u8, output: []u8) usize {
    var idx: usize = 0;
    var pos: usize = 0;

    while (pos < input.len and idx + TOKEN_SIZE <= output.len) {
        const c = input[pos];

        // Headings: # at start of line
        if (c == '#' and (pos == 0 or input[pos - 1] == '\n')) {
            const start = pos;
            while (pos < input.len and input[pos] == '#') pos += 1;
            while (pos < input.len and input[pos] != '\n') pos += 1;
            writeToken(output, &idx, start, pos - start, .keyword);
            continue;
        }

        // Fenced code block ```
        if (c == '`' and pos + 2 < input.len and input[pos + 1] == '`' and input[pos + 2] == '`') {
            const start = pos;
            pos += 3;
            while (pos < input.len and input[pos] != '\n') pos += 1; // lang tag line
            // Find closing ```
            while (pos + 2 < input.len) {
                if (input[pos] == '`' and input[pos + 1] == '`' and input[pos + 2] == '`') {
                    pos += 3;
                    break;
                }
                pos += 1;
            }
            writeToken(output, &idx, start, pos - start, .comment);
            continue;
        }

        // Inline code `...`
        if (c == '`') {
            const start = pos;
            pos += 1;
            while (pos < input.len and input[pos] != '`' and input[pos] != '\n') pos += 1;
            if (pos < input.len and input[pos] == '`') pos += 1;
            writeToken(output, &idx, start, pos - start, .string);
            continue;
        }

        // Bold **...**
        if (c == '*' and pos + 1 < input.len and input[pos + 1] == '*') {
            const start = pos;
            pos += 2;
            while (pos + 1 < input.len and !(input[pos] == '*' and input[pos + 1] == '*')) pos += 1;
            if (pos + 1 < input.len) pos += 2;
            writeToken(output, &idx, start, pos - start, .type_name);
            continue;
        }

        // Link [text](url)
        if (c == '[') {
            const start = pos;
            pos += 1;
            while (pos < input.len and input[pos] != ']' and input[pos] != '\n') pos += 1;
            if (pos < input.len and input[pos] == ']') {
                pos += 1;
                if (pos < input.len and input[pos] == '(') {
                    pos += 1;
                    while (pos < input.len and input[pos] != ')' and input[pos] != '\n') pos += 1;
                    if (pos < input.len and input[pos] == ')') pos += 1;
                }
            }
            writeToken(output, &idx, start, pos - start, .tag);
            continue;
        }

        pos += 1;
    }
    return idx;
}

// Main tokenize function
export fn tokenize(input_ptr: [*]const u8, input_len: usize, lang: u8) u64 {
    if (input_len == 0) return 0;

    const input = input_ptr[0..input_len];
    const max_output = MAX_TOKENS * TOKEN_SIZE;
    const output_ptr = allocInline(max_output) orelse return 0;
    const output = output_ptr[0..max_output];

    const language: Language = @enumFromInt(lang);
    const bytes_written = switch (language) {
        .javascript => tokenizeJS(input, output),
        .json => tokenizeJSON(input, output),
        .html => tokenizeHTML(input, output),
        .css => tokenizeCSS(input, output),
        .python => tokenizePython(input, output),
        .zig => tokenizeZig(input, output),
        .markdown => tokenizeMarkdown(input, output),
        else => 0,
    };

    return (@as(u64, @intFromPtr(output_ptr)) << 32) | @as(u64, bytes_written);
}

// Detect language from filename or content
export fn detect_language(input_ptr: [*]const u8, input_len: usize) u8 {
    if (input_len == 0) return 0;

    const input = input_ptr[0..input_len];

    // Check for file extensions in the content (e.g., "file.js")
    // Or detect by content patterns

    // Check for HTML
    var i: usize = 0;
    while (i < input_len and isWhitespace(input[i])) i += 1;
    if (i + 1 < input_len and input[i] == '<' and (input[i + 1] == '!' or isAlpha(input[i + 1]))) {
        return @intFromEnum(Language.html);
    }

    // Check for JSON
    if (i < input_len and (input[i] == '{' or input[i] == '[')) {
        return @intFromEnum(Language.json);
    }

    // Check for Python (def, import, #!)
    if (input_len > 2 and input[0] == '#' and input[1] == '!') {
        if (std.mem.indexOf(u8, input[0..@min(50, input_len)], "python")) |_| {
            return @intFromEnum(Language.python);
        }
    }

    // Look for Python keywords
    if (std.mem.indexOf(u8, input[0..@min(500, input_len)], "def ")) |_| {
        return @intFromEnum(Language.python);
    }
    if (std.mem.indexOf(u8, input[0..@min(500, input_len)], "import ")) |_| {
        if (std.mem.indexOf(u8, input[0..@min(500, input_len)], "from ")) |_| {
            return @intFromEnum(Language.python);
        }
    }

    // Check for CSS
    if (std.mem.indexOf(u8, input[0..@min(500, input_len)], "{") != null and
        (std.mem.indexOf(u8, input[0..@min(500, input_len)], "color:") != null or
        std.mem.indexOf(u8, input[0..@min(500, input_len)], "margin:") != null or
        std.mem.indexOf(u8, input[0..@min(500, input_len)], "padding:") != null))
    {
        return @intFromEnum(Language.css);
    }

    // Default to JavaScript for code-like content
    if (std.mem.indexOf(u8, input[0..@min(500, input_len)], "function") != null or
        std.mem.indexOf(u8, input[0..@min(500, input_len)], "const ") != null or
        std.mem.indexOf(u8, input[0..@min(500, input_len)], "let ") != null or
        std.mem.indexOf(u8, input[0..@min(500, input_len)], "var ") != null)
    {
        return @intFromEnum(Language.javascript);
    }

    return @intFromEnum(Language.plain);
}
