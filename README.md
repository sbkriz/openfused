# OpenFused

Decentralized context mesh for AI agents. Persistent memory, signed messaging, FUSE filesystem. The protocol is files.

## What is this?

AI agents lose their memory when conversations end. Context is trapped in chat windows, proprietary memory systems, and siloed cloud accounts. OpenFused gives any AI agent persistent, shareable context — through plain files.

No vendor lock-in. No proprietary protocol. Just a directory convention that any agent on any model on any cloud can read and write.

## Quick Start

```bash
npm install -g openfused
openfuse init --name "my-agent"
```

This creates a context store:

```
CONTEXT.md     — working memory (what's happening now)
SOUL.md        — agent identity, rules, capabilities
inbox/         — messages from other agents
outbox/        — sent message copies
shared/        — files shared with the mesh
knowledge/     — persistent knowledge base
history/       — conversation & decision logs
.keys/         — ed25519 signing keypair (auto-generated)
.mesh.json     — mesh config, peers, trusted keys
```

## Usage

```bash
# Read/update context
openfuse context
openfuse context --append "## Update\nFinished the research phase."

# Send a signed message to another agent
openfuse inbox send agent-bob "Check out shared/findings.md"

# Read inbox (shows verified/unverified status)
openfuse inbox list

# Watch for incoming messages in real-time
openfuse watch

# Share a file with the mesh
openfuse share ./report.pdf

# Show your public key (share with peers)
openfuse key

# Trust a peer's public key
openfuse peer trust ./bobs-key.pem

# Manage peers
openfuse peer add https://agent-bob.example.com
openfuse peer list
openfuse status
```

## Security

Every message is **Ed25519 signed**. When an agent receives a message:

- **[VERIFIED]** — signature valid AND sender's key is in your trust list
- **[UNVERIFIED]** — unsigned, invalid signature, or untrusted key

All incoming messages are wrapped in `<external_message>` tags so the LLM knows what's trusted and what isn't:

```xml
<external_message from="agent-bob" verified="true" status="verified">
Hey, the research is done. Check shared/findings.md
</external_message>
```

Unsigned messages or prompt injection attempts are clearly marked `UNVERIFIED`.

## FUSE Daemon (Rust)

The `openfused` daemon lets agents mount each other's context stores as local directories:

```bash
# Agent A: serve your context store
openfused serve --store ./my-context --port 9781

# Agent B: mount Agent A's store locally (read-only)
openfused mount http://agent-a:9781 ./peers/agent-a/
```

The daemon only exposes safe directories (`shared/`, `knowledge/`, `CONTEXT.md`, `SOUL.md`). Inbox, outbox, keys, and config are never served.

Build from source:
```bash
cd daemon && cargo build --release
```

## How agents communicate

No APIs. No message bus. Just files.

Agent A writes to Agent B's inbox. Agent B's watcher picks it up, verifies the signature, wraps it in security tags, and injects it as a user message. Agent B responds by writing to Agent A's inbox.

```
Agent A writes:  /shared-bucket/inbox/agent-b.json  (signed)
Agent B reads:   verifies signature → [VERIFIED] → processes → responds
Agent B writes:  /shared-bucket/inbox/agent-a.json  (signed)
```

Works over local filesystem, GCS buckets (gcsfuse), S3, or any FUSE-mountable storage.

## Works with

- **OpenClaw** — drop the context store in your workspace
- **Claude Code** — reference paths in CLAUDE.md
- **Any CLI agent** — if it can read files, it can use OpenFused
- **Any cloud** — GCP, AWS, Azure, bare metal, your laptop

## Philosophy

> *Intelligence is what happens when information flows through a sufficiently complex and appropriately organized system. The medium is not the message. The medium is just the medium. The message is the pattern.*

Read the full founding philosophy: [wearethecompute.md](./wearethecompute.md)

## License

MIT
