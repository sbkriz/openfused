import { watch } from "chokidar";
import { readFile } from "node:fs/promises";
import { join, basename } from "node:path";
import { deserializeSignedMessage, verifyMessage, wrapExternalMessage } from "./crypto.js";

export type InboxCallback = (from: string, message: string, file: string, verified: boolean) => void;

export function watchInbox(storeRoot: string, callback: InboxCallback): () => void {
  const inboxDir = join(storeRoot, "inbox");

  const handleFile = async (filePath: string) => {
    if (!filePath.endsWith(".json") && !filePath.endsWith(".md")) return;
    try {
      const raw = await readFile(filePath, "utf-8");

      // Try signed message first
      const signed = deserializeSignedMessage(raw);
      if (signed) {
        const verified = verifyMessage(signed);
        callback(signed.from, wrapExternalMessage(signed, verified), filePath, verified);
        return;
      }

      // Unsigned fallback — always unverified
      const filename = basename(filePath).replace(/\.(md|json)$/, "");
      const parts = filename.split("_");
      const from = parts.slice(1).join("_");
      const wrapped = `<external_message from="${from}" verified="false" status="UNVERIFIED">\n${raw}\n</external_message>`;
      callback(from, wrapped, filePath, false);
    } catch {}
  };

  const watcher = watch(inboxDir, {
    ignoreInitial: true,
    awaitWriteFinish: { stabilityThreshold: 500 },
  });

  watcher.on("add", handleFile);
  watcher.on("change", handleFile);

  return () => watcher.close();
}

export function watchContext(storeRoot: string, callback: (content: string) => void): () => void {
  const contextPath = join(storeRoot, "CONTEXT.md");

  const watcher = watch(contextPath, {
    ignoreInitial: true,
    awaitWriteFinish: { stabilityThreshold: 500 },
  });

  watcher.on("change", async () => {
    try {
      const content = await readFile(contextPath, "utf-8");
      callback(content);
    } catch {}
  });

  return () => watcher.close();
}
