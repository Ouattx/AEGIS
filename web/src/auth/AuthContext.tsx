import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AegisClient } from "../api/client";
import type { OidcLoginConfig, Permission, Role } from "../api/types";
import { buildAuthorizationUrl, redirectUri, takePendingLogin } from "./oidc";
import { can, isExpired, loadSession, saveSession, tokenExpiry, type Session } from "./session";

/** Renew an OIDC access token this long before it expires. */
const REFRESH_LEAD_MS = 60_000;

interface AuthState {
  session: Session | null;
  client: AegisClient;
  /** reason the last session ended (expired, revoked), shown on the sign-in screen */
  notice: string | null;
  loginWithToken: (token: string, refreshToken?: string | null) => Promise<void>;
  loginDemo: (role: Role) => Promise<void>;
  /** start the identity provider sign-in (authorization code + PKCE); navigates away */
  loginWithOidc: (cfg: OidcLoginConfig, next: string) => Promise<void>;
  /** finish the sign-in on the callback route; returns the route to continue to */
  completeOidcLogin: (search: string) => Promise<string>;
  logout: (notice?: string) => void;
  can: (p: Permission) => boolean;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children, fetchImpl }: { children: ReactNode; fetchImpl?: typeof fetch }) {
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [notice, setNotice] = useState<string | null>(null);
  const tokenRef = useRef<string | null>(session?.token ?? null);
  tokenRef.current = session?.token ?? null;

  const logout = useCallback((why?: string) => {
    saveSession(null);
    tokenRef.current = null;
    setSession(null);
    setNotice(why ?? null);
  }, []);

  const client = useMemo(
    () =>
      new AegisClient({
        getToken: () => tokenRef.current,
        onUnauthorized: () => logout("Your session expired or was revoked. Sign in again."),
        fetchImpl,
      }),
    [logout, fetchImpl],
  );

  const loginWithToken = useCallback(
    async (token: string, refreshToken?: string | null) => {
      tokenRef.current = token;
      try {
        const me = await client.me();
        const s: Session = { token, me, expiresAt: tokenExpiry(token), refreshToken: refreshToken ?? null };
        saveSession(s);
        setNotice(null);
        setSession(s);
      } catch (exc) {
        tokenRef.current = null;
        throw exc;
      }
    },
    [client],
  );

  const loginDemo = useCallback(
    async (role: Role) => {
      const t = await client.demoToken(role);
      await loginWithToken(t.access_token);
    },
    [client, loginWithToken],
  );

  const loginWithOidc = useCallback(async (cfg: OidcLoginConfig, next: string) => {
    window.location.assign(await buildAuthorizationUrl(cfg, next));
  }, []);

  const completeOidcLogin = useCallback(
    async (search: string) => {
      const { code, pending } = takePendingLogin(search);
      const tok = await client.oidcToken({ grant_type: "authorization_code", code, code_verifier: pending.verifier, redirect_uri: redirectUri() });
      await loginWithToken(tok.access_token, tok.refresh_token ?? null);
      return pending.next || "/";
    },
    [client, loginWithToken],
  );

  // renew an OIDC session shortly before its access token expires (refresh token grant)
  useEffect(() => {
    if (!session?.expiresAt || !session.refreshToken) return;
    const refreshToken = session.refreshToken;
    const ms = Math.max(0, session.expiresAt - Date.now() - REFRESH_LEAD_MS);
    const t = window.setTimeout(async () => {
      try {
        const tok = await client.oidcToken({ grant_type: "refresh_token", refresh_token: refreshToken });
        await loginWithToken(tok.access_token, tok.refresh_token ?? refreshToken);
      } catch {
        logout("Your session could not be renewed. Sign in again.");
      }
    }, Math.min(ms, 2 ** 31 - 1));
    return () => window.clearTimeout(t);
  }, [session, client, loginWithToken, logout]);

  // end the session exactly when the token expires
  useEffect(() => {
    if (!session?.expiresAt) return;
    const ms = session.expiresAt - Date.now();
    if (ms <= 0 || isExpired(session)) {
      logout("Your session expired. Sign in again.");
      return;
    }
    const t = window.setTimeout(() => logout("Your session expired. Sign in again."), Math.min(ms, 2 ** 31 - 1));
    return () => window.clearTimeout(t);
  }, [session, logout]);

  const value = useMemo<AuthState>(
    () => ({
      session,
      client,
      notice,
      loginWithToken,
      loginDemo,
      loginWithOidc,
      completeOidcLogin,
      logout,
      can: (p: Permission) => can(session?.me, p),
    }),
    [session, client, notice, loginWithToken, loginDemo, loginWithOidc, completeOidcLogin, logout],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used inside <AuthProvider>");
  return v;
}

export function useClient(): AegisClient {
  return useAuth().client;
}
