/**
 * Console sign-in with the operator's identity provider: OAuth 2.0 authorization code
 * flow with PKCE (RFC 7636, S256). The browser generates and keeps the code verifier;
 * the code-for-token exchange and refreshes are relayed by the AEGIS API
 * (``POST /api/v1/auth/token``), so the console never needs cross-origin access to the IdP.
 */
import type { OidcLoginConfig } from "../api/types";

export const CALLBACK_PATH = "/auth/callback";
const PENDING_KEY = "aegis.oidc.pending.v1";

export interface PendingLogin {
  state: string;
  verifier: string;
  nonce: string;
  next: string;
  createdAt: number;
}

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Cryptographically random URL-safe string of ``bytes`` bytes of entropy. */
export function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64url(buf);
}

/** PKCE S256 challenge of a verifier: base64url(SHA-256(verifier)). */
export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

export function redirectUri(origin: string = window.location.origin): string {
  return origin.replace(/\/+$/, "") + CALLBACK_PATH;
}

/** Build the authorization request and remember the verifier/state for the callback. */
export async function buildAuthorizationUrl(cfg: OidcLoginConfig, next: string, origin?: string): Promise<string> {
  const pending: PendingLogin = { state: randomToken(24), verifier: randomToken(48), nonce: randomToken(24), next, createdAt: Date.now() };
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
  const url = new URL(cfg.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", cfg.client_id);
  url.searchParams.set("redirect_uri", redirectUri(origin));
  url.searchParams.set("scope", cfg.scopes);
  url.searchParams.set("state", pending.state);
  url.searchParams.set("nonce", pending.nonce);
  url.searchParams.set("code_challenge", await pkceChallenge(pending.verifier));
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

/** Validate the callback query and return the pending login it belongs to (consumed once). */
export function takePendingLogin(search: string, now: number = Date.now()): { code: string; pending: PendingLogin } {
  const params = new URLSearchParams(search);
  const error = params.get("error");
  if (error) throw new Error(`identity provider returned ${error}${params.get("error_description") ? `: ${params.get("error_description")}` : ""}`);
  const code = params.get("code");
  const state = params.get("state");
  const raw = sessionStorage.getItem(PENDING_KEY);
  sessionStorage.removeItem(PENDING_KEY);
  if (!raw) throw new Error("no sign-in in progress in this browser tab");
  const pending = JSON.parse(raw) as PendingLogin;
  if (!code || !state || state !== pending.state) throw new Error("sign-in response does not match the request (state)");
  if (now - pending.createdAt > 10 * 60 * 1000) throw new Error("sign-in took too long; start again");
  return { code, pending };
}
