// A daily scheduled function that prunes expired sessions and stale WebAuthn
// challenges from the blob store. The audit trail is never touched — it's the
// permanent, tamper-evident record.

import type { Config } from "@netlify/functions";
import { kv } from "../lib/store.ts";
import { SESSION_TTL_MS } from "../lib/data.ts";

const CHALLENGE_TTL_MS = 10 * 60 * 1000;

export const config: Config = { schedule: "@daily" };

export default async () => {
  const now = Date.now();
  let removed = 0;

  const sessions = kv("sessions");
  for (const key of await sessions.list()) {
    const s = await sessions.get<{ createdAt: number }>(key);
    if (s && now - s.createdAt > SESSION_TTL_MS) {
      await sessions.delete(key);
      removed++;
    }
  }

  const challenges = kv("challenges");
  for (const key of await challenges.list()) {
    const c = await challenges.get<{ at: number }>(key);
    if (c && now - c.at > CHALLENGE_TTL_MS) {
      await challenges.delete(key);
      removed++;
    }
  }

  return new Response(`pruned ${removed} expired records`);
};
