import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AegisClient } from "../api/client";
import type { Permission, Role } from "../api/types";
import { can, isExpired, loadSession, saveSession, tokenExpiry, type Session } from "./session";

interface AuthState {
  session: Session | null;
  client: AegisClient;
  /** reason the last session ended (expired, revoked), shown on the sign-in screen */
  notice: string | null;
  loginWithToken: (token: string) => Promise<void>;
  loginDemo: (role: Role) => Promise<void>;
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
    async (token: string) => {
      tokenRef.current = token;
      try {
        const me = await client.me();
        const s: Session = { token, me, expiresAt: tokenExpiry(token) };
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
      logout,
      can: (p: Permission) => can(session?.me, p),
    }),
    [session, client, notice, loginWithToken, loginDemo, logout],
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
