// WebAuthn passkeys — phishing-resistant authentication, bound to the origin so
// a credential minted for this site can't be replayed anywhere else. Built on
// @simplewebauthn/server. Credentials and the short-lived ceremony challenges
// live in the blob store; the private key never leaves the user's device.

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { kv } from "./store.ts";

type RegResponse = Parameters<typeof verifyRegistrationResponse>[0]["response"];
type AuthResponse = Parameters<typeof verifyAuthenticationResponse>[0]["response"];
import { getUser } from "./data.ts";

interface StoredCredential {
  id: string; // base64url credential ID
  publicKey: string; // base64url COSE public key
  counter: number;
  transports?: string[];
}

const creds = () => kv("passkeys");
const challenges = () => kv("challenges");
const RP_NAME = "Tessera";

export async function has(userId: string): Promise<boolean> {
  const list = (await creds().get<StoredCredential[]>(userId)) ?? [];
  return list.length > 0;
}

export async function registrationOptions(
  user: { id: string; email: string; name: string },
  rpID: string,
) {
  const existing = (await creds().get<StoredCredential[]>(user.id)) ?? [];
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID,
    userName: user.email,
    userDisplayName: user.name,
    attestationType: "none",
    excludeCredentials: existing.map((c) => ({ id: c.id })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
  });
  await challenges().set(`reg:${user.id}`, { challenge: options.challenge, at: Date.now() });
  return options;
}

export async function verifyRegistration(
  userId: string,
  response: unknown,
  rpID: string,
  origin: string,
): Promise<boolean> {
  const saved = await challenges().get<{ challenge: string }>(`reg:${userId}`);
  if (!saved) return false;
  const verification = await verifyRegistrationResponse({
    response: response as RegResponse,
    expectedChallenge: saved.challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
  });
  if (!verification.verified || !verification.registrationInfo) return false;
  const { credential } = verification.registrationInfo;
  const list = (await creds().get<StoredCredential[]>(userId)) ?? [];
  list.push({
    id: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString("base64url"),
    counter: credential.counter,
    transports: credential.transports,
  });
  await creds().set(userId, list);
  await challenges().delete(`reg:${userId}`);
  return true;
}

export async function authenticationOptions(userId: string, rpID: string) {
  const list = (await creds().get<StoredCredential[]>(userId)) ?? [];
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: list.map((c) => ({ id: c.id, transports: c.transports as never })),
    userVerification: "preferred",
  });
  await challenges().set(`auth:${userId}`, { challenge: options.challenge, at: Date.now() });
  return options;
}

export async function verifyAuthentication(
  userId: string,
  response: unknown,
  rpID: string,
  origin: string,
): Promise<boolean> {
  const user = await getUser(userId);
  if (!user) return false;
  const saved = await challenges().get<{ challenge: string }>(`auth:${userId}`);
  if (!saved) return false;
  const list = (await creds().get<StoredCredential[]>(userId)) ?? [];
  const resp = response as AuthResponse;
  const match = list.find((c) => c.id === resp.id);
  if (!match) return false;
  const verification = await verifyAuthenticationResponse({
    response: resp,
    expectedChallenge: saved.challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    credential: {
      id: match.id,
      publicKey: Buffer.from(match.publicKey, "base64url"),
      counter: match.counter,
      transports: match.transports as never,
    },
  });
  if (!verification.verified) return false;
  match.counter = verification.authenticationInfo.newCounter;
  await creds().set(userId, list);
  await challenges().delete(`auth:${userId}`);
  return true;
}
