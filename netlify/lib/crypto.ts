// Credential primitives, built on Node's crypto. Passwords are salted and
// stretched with PBKDF2-SHA-256; comparisons are constant-time. Nothing here is
// bespoke cryptography — it uses the platform's vetted implementations.

import {
  createHmac,
  pbkdf2Sync,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";

const PBKDF2_ITERATIONS = 210_000; // OWASP 2023 guidance for PBKDF2-SHA-256
const KEYLEN = 32;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const dk = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEYLEN, "sha256");
  return `pbkdf2$${PBKDF2_ITERATIONS}$${salt.toString("base64")}$${dk.toString("base64")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = Number(parts[1]);
  const salt = Buffer.from(parts[2], "base64");
  const expected = Buffer.from(parts[3], "base64");
  const dk = pbkdf2Sync(password, salt, iterations, expected.length, "sha256");
  return expected.length === dk.length && timingSafeEqual(expected, dk);
}

export function newId(prefix = ""): string {
  return prefix + randomUUID();
}

export function newToken(): string {
  return randomBytes(32).toString("base64url");
}

// ---- base32 (RFC 4648) for TOTP secrets ----
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.replace(/=+$/, "").toUpperCase().replace(/\s/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function hmacSha1(key: Buffer, msg: Buffer): Buffer {
  return createHmac("sha1", key).update(msg).digest();
}
