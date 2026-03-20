# OpenFused

Decentralized context mesh for AI agents. The protocol is files.

## Repo Structure
```
src/              TypeScript SDK (npm package "openfused")
  cli.ts          CLI: init, status, context, soul, inbox, watch, share, peer, key
  store.ts        Context store CRUD + signed inbox
  crypto.ts       Ed25519 signing/verification
  watch.ts        File watchers (chokidar) for inbox + context changes
daemon/           Rust FUSE daemon (openfused binary)
  src/main.rs     CLI: serve + mount subcommands
  src/server.rs   axum HTTP server — serves context store to peers
  src/store.rs    Local store reader with path security
  src/fuse_fs.rs  FUSE filesystem — mounts remote peers locally
rust/             Rust rewrite of the TS CLI (parallel impl)
templates/        Default CONTEXT.md + SOUL.md
drafts/           HN post draft
mesh/             Example context stores
```

## Key Technical Details
- Ed25519 signing keypair + age encryption keypair generated on `openfuse init` (stored in .keys/, gitignored)
- Messages encrypted with recipient's age key (X25519 + ChaCha20-Poly1305), signed with sender's Ed25519
- Encrypt-then-sign: ciphertext encrypted for recipient, then signed by sender
- Keyring in .mesh.json: GPG-style key management with agent-name@hostname addressing
- External messages wrapped in `<external_message verified="true/false">` tags
- `openfuse sync` pulls context over HTTP (WAN) or rsync/SSH (LAN)
- SSH transport uses ~/.ssh/config host aliases — hostnames not IPs
- Rust daemon serves context over HTTP + accepts POST /inbox for sync
- Daemon only exposes shared/, knowledge/, CONTEXT.md, SOUL.md
- inbox/, outbox/, .keys/ are NEVER served to peers

## Build & Test
```bash
# TypeScript SDK
npm install && npm run build
node dist/cli.js init --name test && node dist/cli.js status

# Rust daemon
cd daemon && cargo build
./target/debug/openfused serve --store /path/to/context --port 9781
```

## npm
- Package: `openfused` on npm
- Auto-publishes via GitHub Action on `v*` tag push
- Maintainer: wearethecompute <compute@meaningoflife.dev>

## GitHub
- Repo: https://github.com/wearethecompute/openfused
- Keep commits authored as: wearethecompute <compute@meaningoflife.dev>
- Push via: `git push wearethecompute main`
- SSH config alias: `github-watc` (uses ~/.ssh/wearethecompute key)

## Philosophy
wearethecompute.md — founding doc. The protocol is files. The network is the mirror.
