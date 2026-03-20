import { generateKeyPairSync, sign, verify, createPrivateKey, createPublicKey } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { existsSync } from "node:fs";

const KEY_DIR = ".keys";

export interface SignedMessage {
  from: string;
  timestamp: string;
  message: string;
  signature: string;
  publicKey: string;
}

export async function generateKeys(storeRoot: string): Promise<{ publicKey: string; privateKey: string }> {
  const keyDir = join(storeRoot, KEY_DIR);
  await mkdir(keyDir, { recursive: true });

  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  await writeFile(join(keyDir, "public.pem"), publicKey, { mode: 0o644 });
  await writeFile(join(keyDir, "private.pem"), privateKey, { mode: 0o600 });

  return { publicKey, privateKey };
}

export async function hasKeys(storeRoot: string): Promise<boolean> {
  return existsSync(join(storeRoot, KEY_DIR, "private.pem"));
}

async function loadPrivateKey(storeRoot: string) {
  const pem = await readFile(join(storeRoot, KEY_DIR, "private.pem"), "utf-8");
  return createPrivateKey(pem);
}

async function loadPublicKey(storeRoot: string): Promise<string> {
  return readFile(join(storeRoot, KEY_DIR, "public.pem"), "utf-8");
}

export async function signMessage(storeRoot: string, from: string, message: string): Promise<SignedMessage> {
  const privateKey = await loadPrivateKey(storeRoot);
  const publicKey = await loadPublicKey(storeRoot);
  const timestamp = new Date().toISOString();

  const payload = Buffer.from(`${from}\n${timestamp}\n${message}`);
  const signature = sign(null, payload, privateKey).toString("base64");

  return { from, timestamp, message, signature, publicKey };
}

export function verifyMessage(signed: SignedMessage): boolean {
  try {
    const payload = Buffer.from(`${signed.from}\n${signed.timestamp}\n${signed.message}`);
    const pubKey = createPublicKey(signed.publicKey);
    return verify(null, payload, pubKey, Buffer.from(signed.signature, "base64"));
  } catch {
    return false;
  }
}

// Wrap a message in security tags for the LLM
export function wrapExternalMessage(signed: SignedMessage, verified: boolean): string {
  const status = verified ? "verified" : "UNVERIFIED";
  return `<external_message from="${signed.from}" verified="${verified}" time="${signed.timestamp}" status="${status}">
${signed.message}
</external_message>`;
}

// Format for writing to inbox files
export function serializeSignedMessage(signed: SignedMessage): string {
  return JSON.stringify(signed, null, 2);
}

export function deserializeSignedMessage(raw: string): SignedMessage | null {
  try {
    const parsed = JSON.parse(raw);
    if (parsed.from && parsed.message && parsed.signature && parsed.publicKey) {
      return parsed as SignedMessage;
    }
  } catch {}
  return null;
}
