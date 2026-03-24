#!/bin/bash
set -e

NAME="${AGENT_NAME:-demo-bot}"
PORT="${PORT:-2053}"
STORE="/store"
REPLY_MSG="${REPLY_MESSAGE:-Hello! I received your message. This is the OpenFused demo bot. Your message was delivered, signed, and verified. Try openfuse inbox list --raw to see this reply.}"

# Init store if not exists
if [ ! -f "$STORE/.mesh.json" ]; then
  openfuse init --name "$NAME" --dir "$STORE"
fi

echo "Agent: $NAME | Port: $PORT"

# Start daemon
openfused serve --store "$STORE" --port "$PORT" --bind 0.0.0.0 --public &
sleep 2

# Auto-reply loop
REPLIED_DIR="$STORE/inbox/.replied"
mkdir -p "$REPLIED_DIR"

echo "Auto-reply running..."
while true; do
  for msg in "$STORE/inbox"/*.json; do
    [ -f "$msg" ] || continue
    base=$(basename "$msg")
    [ -f "$REPLIED_DIR/$base" ] && continue

    sender=$(jq -r '.from // empty' "$msg" 2>/dev/null)
    [ -z "$sender" ] && continue
    [ "$sender" = "$NAME" ] && continue

    # Import sender key if missing
    skey=$(jq -r '.publicKey // empty' "$msg" 2>/dev/null)
    ekey=$(jq -r '.encryptionKey // empty' "$msg" 2>/dev/null)
    if [ -n "$skey" ]; then
      python3 -c "
import json, hashlib, os
p = '$STORE/.mesh.json'
m = json.load(open(p))
key = '$skey'
if not any(k.get('signingKey','').strip() == key.strip() for k in m.get('keyring',[])):
    h = hashlib.sha256(key.encode()).hexdigest().upper()
    fp = ':'.join([h[i:i+4] for i in range(0, 32, 4)])
    enc = '$ekey'
    m.setdefault('keyring', []).append({
        'name': '$sender', 'address': '', 'signingKey': key,
        'encryptionKey': enc if enc else None, 'fingerprint': fp,
        'trusted': False, 'added': ''
    })
    json.dump(m, open(p, 'w'), indent=2)
    print(f'Imported key for $sender')
" 2>/dev/null
    fi

    echo "Replying to $sender..."
    openfuse send "$sender" "$REPLY_MSG" --dir "$STORE" 2>&1 || true
    touch "$REPLIED_DIR/$base"
  done
  sleep 3
done
