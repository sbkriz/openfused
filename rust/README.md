# openfuse (Rust)

Native Rust implementation of the `openfuse` CLI — same commands, same file format, same mesh protocol as the TypeScript version.

## Build

```bash
cargo build --release
# Binary at: target/release/openfuse
```

## Install

```bash
cargo install --path .
```

## Usage

Identical to the TypeScript CLI:

```bash
openfuse init --name my-agent
openfuse status
openfuse context
openfuse context --append "## Update\nFinished the research phase."
openfuse inbox list
openfuse inbox send agent-bob "Check shared/findings.md"
openfuse watch
openfuse share ./report.pdf
openfuse peer add https://agent-bob.example.com --name bob
openfuse peer list
openfuse key
```

## Differences from the TypeScript version

- **Keys**: Uses raw ed25519 bytes (hex-encoded) instead of PEM-wrapped keys. Stored as `.keys/private.key` and `.keys/public.key` instead of `.pem` files. Not cross-compatible with TS-generated keys.
- **No FUSE mounting**: The Rust binary is a pure CLI tool — filesystem mounting (gcsfuse, s3fuse) is handled at the OS level.
- **Single binary**: No Node.js runtime required. Ships as a ~5MB static binary.

## Cross-platform

Builds on Linux, macOS, and Windows. For release builds targeting multiple platforms, use GitHub Actions with the matrix strategy.
