# WASM Prover Test

Minimal test harness to verify the Miden VM prover works in WASM (browser) environments.

## Prerequisites

```bash
cargo install wasm-pack

# Install a browser driver (one of):
brew install geckodriver    # Firefox
brew install chromedriver   # Chrome

# If chromedriver is quarantined on macOS:
xattr -d com.apple.quarantine $(which chromedriver)
```

## Running

```bash
cd crates/wasm-prover-test

# Firefox (recommended)
wasm-pack test --firefox --headless --release

# Chrome
wasm-pack test --chrome --headless --release
```

`--release` is required because the debug WASM binary exceeds the browser's local variable limit.
