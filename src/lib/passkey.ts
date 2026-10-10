// Browser side of the WebAuthn ceremonies.
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { api } from "./api.ts";
import type { Context } from "../../shared/types.ts";

export async function registerPasskey(): Promise<boolean> {
  const options = await fetch("/api/passkey/register/options", {
    method: "POST",
    credentials: "same-origin",
  }).then((r) => r.json());
  const response = await startRegistration({ optionsJSON: options });
  const res = await fetch("/api/passkey/register/verify", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ response }),
  }).then((r) => r.json());
  return !!res.ok;
}

export async function loginWithPasskey(email: string, context: Context) {
  const start = await fetch("/api/passkey/login/options", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  }).then((r) => r.json());
  if (start.error) throw new Error(start.error);
  const response = await startAuthentication({ optionsJSON: start.options });
  const res = await fetch("/api/passkey/login/verify", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ userId: start.userId, response, context }),
  }).then((r) => r.json());
  if (res.error) throw new Error(res.error);
  await api.me();
  return res.user;
}
