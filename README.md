# gitText - Shareable Text Editor (https://amiyamandal-dev.github.io/gitText/)

A text editor where the entire document state is compressed and stored in the URL fragment. Share the URL to share the exact document state.

## Features

- **URL State Storage**: Text is automatically compressed and saved to the URL
- **LZSS Compression**: Efficient text compression (50-70% reduction)
- **Base64URL Encoding**: URL-safe encoding for sharing
- **No Server Required**: Everything runs client-side
- **Instant Sharing**: Copy the URL to share your text

## Build

Requires [Zig](https://ziglang.org/) (0.15.0 or later).

```bash
zig build
```

This compiles the WASM module and places it in the `web/` directory.

## Run

Serve the `web/` directory with any static file server:

```bash
cd web
python3 -m http.server 8000
```

Then open http://localhost:8000

## Usage

1. Type or paste text into the editor
2. The URL automatically updates with compressed content (debounced 500ms)
3. Copy the URL using the "Copy Link" button or Ctrl/Cmd+Shift+C
4. Share the URL - anyone opening it sees the exact same text

## Keyboard Shortcuts

- `Ctrl/Cmd + S` - Force save to URL
- `Ctrl/Cmd + Shift + C` - Copy shareable link

## Technical Details

### Compression Pipeline

**Save**: Text -> UTF-8 -> LZSS compress -> Base64URL encode -> URL fragment

**Load**: URL fragment -> Base64URL decode -> LZSS decompress -> UTF-8 -> Text

### LZSS Parameters

- Window size: 4096 bytes
- Min match length: 3 bytes
- Max match length: 18 bytes

### URL Format

```
https://example.com/editor/#eJzLSM3JyQcABiwCFQ
                            └── base64url encoded compressed data
```

## File Structure

```
gitText/
├── src/
│   └── main.zig          # WASM module: compression, encoding
├── web/
│   ├── index.html        # Editor UI
│   ├── app.js            # WASM loader, editor logic
│   └── editor.wasm       # Compiled WASM (after build)
├── build.zig             # Zig build configuration
└── README.md
```

## Limitations

- URL length is practically limited by browsers (~2000-8000 chars depending on browser)
- Very large documents may exceed URL limits
- No syntax highlighting (plain text only)
