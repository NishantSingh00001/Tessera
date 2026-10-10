// RFC 6238 time-based one-time passwords (TOTP) over RFC 4226 HOTP, SHA-1,
// 6 digits, 30-second steps — the scheme Google Authenticator and the like use.

import { base32Decode, base32Encode, hmacSha1 } from "./crypto.ts";
import { randomBytes } from "node:crypto";

const DIGITS = 6;
const STEP = 30;

export function newSecret(): string {
  return base32Encode(randomBytes(20)); // 160-bit secret
}

function hotp(secret: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  // write the counter as a big-endian 64-bit integer
  msg.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  msg.writeUInt32BE(counter >>> 0, 4);
  const hash = hmacSha1(secret, msg);
  const offset = hash[hash.length - 1] & 0x0f;
  const bin =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);
  return (bin % 10 ** DIGITS).toString().padStart(DIGITS, "0");
}

export function totpAt(secretB32: string, timeMs: number = Date.now()): string {
  const counter = Math.floor(timeMs / 1000 / STEP);
  return hotp(base32Decode(secretB32), counter);
}

/** Accept the current code and one step either side, to tolerate clock drift. */
export function verifyTotp(secretB32: string, code: string, timeMs: number = Date.now()): boolean {
  const clean = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(clean)) return false;
  const secret = base32Decode(secretB32);
  const counter = Math.floor(timeMs / 1000 / STEP);
  for (let w = -1; w <= 1; w++) {
    if (hotp(secret, counter + w) === clean) return true;
  }
  return false;
}

/** otpauth:// URI so the secret can be added to an authenticator app via QR. */
export function otpauthUri(secretB32: string, label: string, issuer = "Postern"): string {
  const l = encodeURIComponent(`${issuer}:${label}`);
  return `otpauth://totp/${l}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&digits=${DIGITS}&period=${STEP}`;
}
