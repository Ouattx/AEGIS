import { beforeEach, describe, expect, it } from "vitest";
import { buildAuthorizationUrl, pkceChallenge, randomToken, redirectUri, takePendingLogin } from "./oidc";

const CFG = { client_id: "aegis-console", scopes: "openid offline_access", authorization_endpoint: "https://idp.example/auth", end_session_endpoint: null };

describe("OIDC PKCE helpers", () => {
  beforeEach(() => sessionStorage.clear());

  it("computes the RFC 7636 S256 challenge", async () => {
    // RFC 7636 appendix B test vector
    expect(await pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("produces url-safe random tokens", () => {
    const t = randomToken(48);
    expect(t).toMatch(/^[A-Za-z0-9_-]{64}$/);
    expect(randomToken(48)).not.toBe(t);
  });

  it("builds the authorization request and validates the callback once", async () => {
    const url = new URL(await buildAuthorizationUrl(CFG, "/cases", "https://aegis.isp.example"));
    expect(url.origin + url.pathname).toBe("https://idp.example/auth");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("redirect_uri")).toBe("https://aegis.isp.example/auth/callback");
    const state = url.searchParams.get("state") as string;
    const { code, pending } = takePendingLogin(`?code=abc&state=${state}`);
    expect(code).toBe("abc");
    expect(pending.next).toBe("/cases");
    expect(await pkceChallenge(pending.verifier)).toBe(url.searchParams.get("code_challenge"));
    // consumed: a replayed callback is refused
    expect(() => takePendingLogin(`?code=abc&state=${state}`)).toThrow(/no sign-in in progress/);
  });

  it("refuses a mismatched state or an IdP error", async () => {
    await buildAuthorizationUrl(CFG, "/");
    expect(() => takePendingLogin("?code=abc&state=forged")).toThrow(/state/);
    await buildAuthorizationUrl(CFG, "/");
    expect(() => takePendingLogin("?error=access_denied")).toThrow(/access_denied/);
    expect(redirectUri("https://x.example/")).toBe("https://x.example/auth/callback");
  });
});
