import { watch } from "chokidar";
import { readFile } from "node:fs/promises";
import { join, basename } from "node:path";
import { deserializeSignedMessage, verifyMessage, wrapExternalMessage } from "./crypto.js";
import { syncAll } from "./sync.js";
import { ContextStore } from "./store.js";

export type InboxCallback = (from: string, message: string, file: string, verified: boolean) => void;

export function watchInbox(storeRoot: string, callback: InboxCallback): () => void {
  const inboxDir = join(storeRoot, "inbox");

  const handleFile = async (filePath: string) => {
    if (!filePath.endsWith(".json") && !filePath.endsWith(".md")) return;
    try {
      const raw = await readFile(filePath, "utf-8");

      const signed = deserializeSignedMessage(raw);
      if (signed) {
        const verified = verifyMessage(signed);
        callback(signed.from, wrapExternalMessage(signed, verified), filePath, verified);
        return;
      }

      // Unsigned fallback
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

/**
 * Periodically sync with all peers — pull their context, push our outbox.
 * Returns a cleanup function to stop the interval.
 */
export function watchSync(
  store: ContextStore,
  intervalMs: number,
  onSync: (peerName: string, pulled: string[], pushed: string[]) => void,
  onError: (peerName: string, errors: string[]) => void,
): () => void {
  let running = false;

  const doSync = async () => {
    if (running) return; // skip if previous sync still in progress
    running = true;
    try {
      const results = await syncAll(store);
      for (const r of results) {
        if (r.pulled.length || r.pushed.length) {
          onSync(r.peerName, r.pulled, r.pushed);
        }
        if (r.errors.length) {
          onError(r.peerName, r.errors);
        }
      }
    } catch {}
    running = false;
  };

  // Initial sync immediately
  doSync();

  const timer = setInterval(doSync, intervalMs);
  return () => clearInterval(timer);
}
