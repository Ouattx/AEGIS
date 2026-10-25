import { describe, expect, it } from "vitest";
import { can, isExpired, loadSession, saveSession, tokenExpiry } from "./session";
import type { Me } from "../api/types";

function jwt(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64({ alg: "HS256" })}.${b64(claims)}.sig`;
}

const me: Me = { sub: "demo-analyst", tenant_id: "demo", roles: ["analyst"], auth_mode: "dev", permissions: ["read", "case_work"] };

describe("session", () => {
  it("reads the exp claim", () => {
    expect(tokenExpiry(jwt({ exp: 1792954063 }))).toBe(1792954063000);
    expect(tokenExpiry(jwt({ sub: "x" }))).toBeNull();
    expect(tokenExpiry("not-a-jwt")).toBeNull();
    expect(tokenExpiry("a.%%%.c")).toBeNull();
  });

  it("round-trips through session storage and drops expired sessions", () => {
    const future = { token: "t", me, expiresAt: Date.now() + 60_000 };
    saveSession(future);
    expect(loadSession()).toEqual(future);
    saveSession({ ...future, expiresAt: Date.now() - 1 });
    expect(loadSession()).toBeNull();
    saveSession(null);
    expect(loadSession()).toBeNull();
    sessionStorage.setItem("aegis.session.v1", "{broken");
    expect(loadSession()).toBeNull();
  });

  it("checks expiry and permissions", () => {
    expect(isExpired({ token: "t", me, expiresAt: null })).toBe(false);
    expect(isExpired({ token: "t", me, expiresAt: 10 }, 11)).toBe(true);
    expect(can(me, "case_work")).toBe(true);
    expect(can(me, "approve")).toBe(false);
    expect(can(null, "read")).toBe(false);
  });
});
