import type { Me, Permission } from "../api/types";

const KEY = "aegis.session.v1";

export interface Session {
  token: string;
  me: Me;
  /** epoch milliseconds when the token stops being accepted (from the JWT ``exp`` claim) */
  expiresAt: number | null;
  /** OIDC refresh token (browser sign-in only): renews the access token before it expires */
  refreshToken?: string | null;
}

/** Decode the ``exp`` claim of a JWT without verifying it (the API verifies every request). */
export function tokenExpiry(token: string): number | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const claims = JSON.parse(atob(padded)) as { exp?: unknown };
    return typeof claims.exp === "number" ? claims.exp * 1000 : null;
  } catch {
    return null;
  }
}

export function isExpired(session: Session, now: number = Date.now()): boolean {
  return session.expiresAt !== null && session.expiresAt <= now;
}

export function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as Session;
    if (!s || typeof s.token !== "string" || !s.me) return null;
    return isExpired(s) ? null : s;
  } catch {
    return null;
  }
}

export function saveSession(s: Session | null): void {
  try {
    if (s) sessionStorage.setItem(KEY, JSON.stringify(s));
    else sessionStorage.removeItem(KEY);
  } catch {
    /* storage unavailable (private mode): the session lives in memory only */
  }
}

export function can(me: Me | null | undefined, permission: Permission): boolean {
  return !!me && me.permissions.includes(permission);
}
