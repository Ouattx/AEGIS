import { describe, expect, it, vi } from "vitest";
import { AegisClient, ApiError, buildQuery, describeError } from "./client";

function res(status: number, body: unknown, text = false) {
  return new Response(text ? String(body) : JSON.stringify(body), { status, headers: { "Content-Type": text ? "text/html" : "application/json" } });
}

describe("api client", () => {
  it("builds query strings without empty values", () => {
    expect(buildQuery({ a: 1, b: "", c: null, d: undefined, e: "x y", f: false })).toBe("?a=1&e=x+y&f=false");
    expect(buildQuery({})).toBe("");
    expect(buildQuery()).toBe("");
  });

  it("sends the bearer token and JSON bodies", async () => {
    const f = vi.fn().mockResolvedValue(res(200, { case_id: "c1" }));
    const c = new AegisClient({ getToken: () => "tok", fetchImpl: f });
    await c.transition("c1", "VERIFIED", "because");
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("/api/v1/cases/c1/transition");
    expect(init.method).toBe("POST");
    expect(init.headers.Authorization).toBe("Bearer tok");
    expect(JSON.parse(init.body)).toEqual({ to_state: "VERIFIED", reason: "because" });
  });

  it("encodes path segments and graph nodes", async () => {
    const f = vi.fn().mockImplementation(() => Promise.resolve(res(200, {})));
    const c = new AegisClient({ getToken: () => null, fetchImpl: f });
    await c.graph("domain:evil.example", "2026-10-25T00:00:00.000Z");
    await c.caseDetail("a/b");
    expect(f.mock.calls[0][0]).toBe("/api/v1/graph/domain%3Aevil.example?as_of=2026-10-25T00%3A00%3A00.000Z");
    expect(f.mock.calls[1][0]).toBe("/api/v1/cases/a%2Fb");
    expect(f.mock.calls[0][1].headers.Authorization).toBeUndefined();
  });

  it("parses refusals with failed checks", async () => {
    const f = vi.fn().mockResolvedValue(res(409, { error: "refused", detail: "execution refused", failed_checks: ["case_state:PROPOSED"], request_id: "r1" }));
    const c = new AegisClient({ getToken: () => "tok", fetchImpl: f });
    const err = await c.execute("a1", "").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 409, code: "refused", failedChecks: ["case_state:PROPOSED"], requestId: "r1" });
    expect(describeError(err)).toBe("execution refused — failed checks: case_state:PROPOSED");
  });

  it("reports validation errors and non-JSON failures", async () => {
    const f = vi
      .fn()
      .mockResolvedValueOnce(res(422, { error: "invalid", detail: "request validation failed", errors: [{ loc: ["body", "reason"], msg: "too short", type: "x" }] }))
      .mockResolvedValueOnce(new Response("<html>bad gateway</html>", { status: 502 }));
    const c = new AegisClient({ getToken: () => "tok", fetchImpl: f });
    const e1 = await c.approve("a", "").catch((e) => e);
    expect(describeError(e1)).toBe("request validation failed — reason: too short");
    const e2 = await c.metrics().catch((e) => e);
    expect(e2).toMatchObject({ status: 502, code: "http_502" });
  });

  it("signals 401 only for authenticated calls and wraps network errors", async () => {
    const onUnauthorized = vi.fn();
    const f = vi.fn().mockResolvedValue(res(401, { error: "unauthenticated", detail: "expired" }));
    await new AegisClient({ getToken: () => "tok", onUnauthorized, fetchImpl: f }).me().catch(() => undefined);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    await new AegisClient({ getToken: () => null, onUnauthorized, fetchImpl: f }).me().catch(() => undefined);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    const down = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    const err = await new AegisClient({ getToken: () => null, fetchImpl: down }).authConfig().catch((e) => e);
    expect(err).toMatchObject({ status: 0, code: "network_error" });
  });

  it("requests the PoV report as JSON or HTML", async () => {
    const f = vi.fn().mockResolvedValueOnce(res(200, { schema: "aegis.pov_report/1" })).mockResolvedValueOnce(res(200, "<html>r</html>", true));
    const c = new AegisClient({ getToken: () => "tok", fetchImpl: f });
    expect(await c.povJson({ operator: "ACME" })).toEqual({ schema: "aegis.pov_report/1" });
    expect(await c.povHtml({})).toBe("<html>r</html>");
    expect(f.mock.calls[0][0]).toBe("/api/v1/reports/pov?operator=ACME&format=json");
    expect(f.mock.calls[1][0]).toBe("/api/v1/reports/pov?format=html");
    expect(f.mock.calls[1][1].headers.Accept).toBe("text/html");
  });
});
