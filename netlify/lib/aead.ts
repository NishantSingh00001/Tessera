// Authenticated encryption for data at rest (AES-256-GCM). Stored secrets — the
// TOTP seeds — are sealed with a server key so a leak of the blob store alone
// does not expose them. The key comes from the TESSERA_KEY environment variable
// in production; a fixed development key is used otherwise so the demo runs.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

function key(): Buffer {
  const env = process.env.TESSERA_KEY;
  // Derive a 32-byte key from the env secret, or a clearly-marked dev default.
  return createHash("sha256")
    .update(env || "tessera-development-key-not-for-production")
    .digest();
}

export function seal(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `gcm$${iv.toString("base64")}$${tag.toString("base64")}$${ct.toString("base64")}`;
}

export function open(sealed: string): string {
  const [scheme, ivB64, tagB64, ctB64] = sealed.split("$");
  if (scheme !== "gcm") throw new Error("bad ciphertext");
  const decipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64")), decipher.final()]).toString(
    "utf8",
  );
}

/** SHA-256 hex of a string — used for the audit hash chain. */
export function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}
