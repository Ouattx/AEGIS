import { vi } from "vitest";
import * as fx from "./fixtures";
import type { Role } from "../api/types";

export type Route = (url: URL, init: RequestInit) => unknown;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/**
 * A fetch double for the AEGIS API: role taken from the bearer token's ``roles`` claim,
 * default fixtures for every read, ``overrides`` (``"METHOD /path"``) for specific calls.
 */
export function fakeApi(overrides: Record<string, Route> = {}) {
  const calls: Array<{ method: string; path: string; body: unknown }> = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://localhost");
    const method = (init.method ?? "GET").toUpperCase();
    const path = url.pathname.replace(/^\/api\/v1/, "");
    calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined });
    const key = `${method} ${path}`;
    if (overrides[key]) {
      const out = overrides[key](url, init);
      return out instanceof Response ? out : json(200, out);
    }
    const auth = (init.headers as Record<string, string> | undefined)?.Authorization;
    const role = auth ? (JSON.parse(atob(auth.split(".")[1])).roles[0] as Role) : null;
    if (method === "GET") {
      if (path === "/auth/config") return json(200, { auth_mode: "dev", oidc_issuer: null, oidc_audience: null, demo: true, roles: ["viewer", "analyst", "approver", "admin", "integration"] });
      if (path === "/demo/token") {
        const r = url.searchParams.get("role") as Role;
        return json(200, { access_token: fx.token(r), token_type: "bearer", expires_in: 3600, role: r, tenant_id: "demo", sub: `demo-${r}` });
      }
      if (!role) return json(401, { error: "unauthenticated", detail: "missing token", failed_checks: [] });
      if (path === "/me") return json(200, fx.me(role));
      if (path === "/metrics/summary") return json(200, fx.metrics);
      if (path === "/ledger/verify") return json(200, fx.ledger);
      if (path === "/policies") return json(200, { items: [fx.shadowPolicy], total: 1 });
      if (path === "/reports/pov") return json(200, fx.pov);
      if (path === "/findings") return json(200, { items: [fx.finding], total: 1, limit: 50, offset: 0 });
      if (path === "/cases") return json(200, { items: [fx.caseDetail().case], total: 1, limit: 50, offset: 0 });
      if (path === "/cases/case-1") return json(200, fx.caseDetail());
      if (path === "/cases/case-1/evidence") return json(200, { items: fx.evidence, total: 2 });
      if (path === "/cases/case-1/history") return json(200, { items: [], total: 0 });
      if (path === "/cases/case-1/investigation") return json(200, fx.report);
      if (path === "/actions/act-1") return json(200, fx.action);
    }
    return json(404, { error: "not_found", detail: `no fake for ${key}`, failed_checks: [] });
  });
  return { fetchImpl, calls };
}
