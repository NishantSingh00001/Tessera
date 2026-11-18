# Security review — 20-point pen-test checklist (2026-11-19)

**Stack for this review:** Netlify Functions (TypeScript), Netlify Blobs (no SQL database),
password auth (PBKDF2-SHA-256) + RFC 6238 TOTP + WebAuthn passkeys, AES-256-GCM for data at rest.
No SAML, OAuth, GraphQL, or XML parsing. This app actually implements several of the primitives
the checklist is about (TOTP, password hashing, encryption, token generation), so more of the 20
apply here than to the other repos — and one is a real finding.

| # | Check | Applies? | Finding |
|---|---|---|---|
| 1 | HTTP/2 Rapid Reset | No | Netlify Functions, no server of our own. |
| 2 | bcrypt 72-byte limit | No | Passwords are hashed with PBKDF2-SHA-256 (210k iterations), not bcrypt — this specific truncation bug doesn't exist in PBKDF2. |
| 3 | SAML signature bypass | No | No SAML. |
| 4 | nOAuth | No | No OAuth login. |
| 5 | GraphQL alias batching | No | No GraphQL. |
| 6 | TOTP replay | **Finding** | `verifyTotp()` (`netlify/lib/totp.ts`) checks the current 30-second step and one step either side, but accepting a code never invalidates it — nothing stores "last accepted step per user," so the *same* 6-digit code can be replayed again within its ~90-second window (e.g. captured over the wire or by someone glancing at a screen). Also, `/api/verify` calls `verifyTotp` directly with no lockout: the login endpoint has `checkLock`/`recordFail` (`data.ts`), but the TOTP-verification endpoint doesn't share it, so there's no attempt limit on guessing the 6-digit code itself. **Suggested fix** (not made — needs your OK): store `lastAcceptedStep` per user alongside the sealed secret, reject a code whose step number isn't strictly greater than the stored one, and extend `checkLock`/`recordFail` to key on the TOTP step too. |
| 7 | ReDoS | No | The few regexes in the repo (`\s` strip in `totp.ts`, path cleanup in `api.mts`) are short and non-nested. |
| 8 | JWT algorithm confusion | No | Sessions are opaque random tokens (`newToken()`, 32 random bytes) looked up server-side, not JWTs — there's no algorithm for an attacker to confuse. |
| 9 | HTTP request smuggling | No | No reverse proxy of our own in front of the Functions. |
| 10 | Web cache poisoning | No | No CDN caching of API responses; nothing is built from forwarded headers. |
| 11 | Spoofed X-Forwarded-For | No | No IP-based rate limiting at all — login lockout (`checkLock`) keys on the email being attempted, not an IP, so there's no `X-Forwarded-For` trust decision to get wrong. |
| 12 | Postgres views / RLS | No | No database — storage is Netlify Blobs. |
| 13 | Math.random() for security tokens | **Already handled** | Session tokens (`newToken`), user/record ids (`newId`), TOTP secrets (`newSecret`), and WebAuthn challenges (via `@simplewebauthn/server`) all use `node:crypto` (`randomBytes`/`randomUUID`), never `Math.random()`. |
| 14 | Timing attacks on secret comparison | **Partial finding** | Password verification correctly uses `timingSafeEqual` (`crypto.ts`). TOTP verification does not: `hotp(secret, counter + w) === clean` in `totp.ts` is a plain string `===` compare. The practical exposure is small (6-digit codes, and the login step in front of it is already locked/rate-limited), but it's the same anti-pattern the check is about — worth switching to a constant-time comparison for consistency with the rest of the codebase. Not changed without your OK. |
| 15 | Padding oracle | **Already handled** | TOTP secrets are sealed with AES-256-GCM (authenticated encryption), not CBC (`aead.ts`) — exactly the fix the checklist asks for instead of a padding oracle risk. `open()` does distinguish a bad-scheme error from a failed-auth-tag error in its thrown message, but this only runs server-side against the server's own stored ciphertext, never against attacker-supplied input, so there's no external decryption oracle to exploit either way. |
| 16 | Server-side prototype pollution | No | Request bodies are destructured into named fields (`const { email, password } = await readJson(...)`) rather than merged into a shared object, and the one spread (`{ ...DEFAULT_CONTEXT, ...context }` in `api.mts`) is a JS object-literal spread, which creates plain own data properties and does not invoke the `Object.prototype.__proto__` setter the way `obj[key] = value` can — so a `"__proto__"` key in the request body can't pollute the prototype this way. |
| 17 | Server-side template injection | No | No server-side templating. |
| 18 | XXE | No | No XML parsing. |
| 19 | Cross-site WebSocket hijacking | No | No WebSockets. |
| 20 | Unicode username normalization | No | Usernames are fixed demo personas (emails), not open registration — no normalization edge case to hit. |

## Also worth knowing (not part of the 20)

- The shared demo password (`Sandbox#2026`) and the auto-filled 2FA code are documented in the
  README on purpose — this is a sandbox with five fixed personas, not a real credential boundary,
  so that's not a finding, just worth not mistaking for one.
- The audit log is a hash-chained ledger (`data.ts`), checked for tamper on read — a nice touch
  beyond what the checklist asks for.

No fixes made in this pass — #6 and the TOTP half of #14 are real, low-to-moderate severity
findings on a demo app; let me know which (if any) you want fixed and I'll do them one at a time
with tests after each, per your usual workflow.
