import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { enforcementMode } from "../components/status";
import { fakeApi } from "./fakeApi";
import { caseDetail, shadowPolicy } from "./fixtures";
import { renderApp } from "./render";

describe("console", () => {
  it("redirects to the role picker and signs in with a demo token", async () => {
    const api = fakeApi();
    renderApp("/", api.fetchImpl as unknown as typeof fetch);
    fireEvent.click(await screen.findByTestId("role-analyst"));
    expect(await screen.findByTestId("kpi-devices")).toHaveTextContent("120");
    expect(screen.getByTestId("mode-pill")).toHaveTextContent(/shadow mode/i);
    await waitFor(() => expect(screen.getByTestId("ledger-pill")).toHaveTextContent(/ledger verified/i));
    expect(screen.getByTestId("user-chip")).toHaveTextContent("demo-analyst");
    expect(api.calls.some((c) => c.path === "/demo/token")).toBe(true);
    await waitFor(() => expect(screen.getByTestId("kpi-false-alerts")).toHaveTextContent("0.0"));
  });

  it("signs out on a 401 and shows why", async () => {
    const api = fakeApi({ "GET /metrics/summary": () => new Response(JSON.stringify({ error: "unauthenticated", detail: "expired" }), { status: 401 }) });
    renderApp("/", api.fetchImpl as unknown as typeof fetch, "viewer");
    expect(await screen.findByText(/session expired or was revoked/i)).toBeInTheDocument();
    expect(screen.getByTestId("role-viewer")).toBeInTheDocument();
  });

  it("gates case transitions by role", async () => {
    const viewer = fakeApi();
    const { unmount } = renderApp("/cases/case-1", viewer.fetchImpl as unknown as typeof fetch, "viewer");
    const buttons = await screen.findByTestId("transition-buttons");
    expect(within(buttons).getByTestId("transition-REJECTED")).toBeDisabled();
    expect(screen.queryByTestId("btn-review")).toBeNull();
    unmount();

    const analyst = fakeApi();
    renderApp("/cases/case-1", analyst.fetchImpl as unknown as typeof fetch, "analyst");
    expect(await screen.findByTestId("transition-REJECTED")).toBeEnabled();
    // VERIFIED waits for the counter-hypothesis review
    expect(screen.getByTestId("transition-VERIFIED")).toBeDisabled();
    expect(screen.getByTestId("btn-review")).toBeInTheDocument();
    expect(screen.getByTestId("hypothesis")).toHaveTextContent("Legitimate push heartbeat");
  });

  it("submits a transition with its reason and shows a refusal with failed checks", async () => {
    const api = fakeApi({
      "POST /cases/case-1/transition": () =>
        new Response(JSON.stringify({ error: "refused", detail: "transition refused", failed_checks: ["needs_two_independent_origins_or_signed_ioc_hit"], request_id: "r" }), { status: 409 }),
    });
    renderApp("/cases/case-1", api.fetchImpl as unknown as typeof fetch, "analyst");
    fireEvent.click(await screen.findByTestId("transition-REJECTED"));
    fireEvent.change(screen.getByTestId("reason-input"), { target: { value: "benign CDN" } });
    fireEvent.click(screen.getByTestId("reason-confirm"));
    expect(await screen.findByText(/needs two independent evidence origins/i)).toBeInTheDocument();
    const call = api.calls.find((c) => c.method === "POST");
    expect(call?.body).toEqual({ to_state: "REJECTED", reason: "benign CDN" });
  });

  it("shows the evidence trail with integrity results and independence groups", async () => {
    const api = fakeApi();
    renderApp("/cases/case-1", api.fetchImpl as unknown as typeof fetch, "viewer");
    fireEvent.click(await screen.findByTestId("tab-evidence"));
    const table = await screen.findByTestId("evidence-table");
    expect(table).toHaveTextContent("verified");
    expect(table).toHaveTextContent("FAILED");
    expect(table).toHaveTextContent("grp:alpha");
    expect(table).toHaveTextContent("Signed IOC match");
  });

  it("renders the authorization checklist and blocks approval when not allowed", async () => {
    const api = fakeApi({ "GET /cases/case-1": () => caseDetail("PROPOSED", true) });
    renderApp("/actions/act-1", api.fetchImpl as unknown as typeof fetch, "approver");
    const panel = await screen.findByTestId("authz-panel");
    expect(panel).toHaveTextContent("not allowed");
    expect(panel).toHaveTextContent("policy_not_active_mode");
    await waitFor(() => expect(screen.getByTestId("btn-deny")).toBeEnabled());
    expect(screen.getByTestId("btn-approve")).toBeDisabled();
    expect(screen.getByTestId("mirror-panel")).toHaveTextContent("SAFE");
    expect(screen.getByTestId("btn-execute")).toBeDisabled();
  });

  it("denies the console to integration identities", async () => {
    const api = fakeApi();
    renderApp("/", api.fetchImpl as unknown as typeof fetch, "integration");
    expect(await screen.findByText(/cannot use the console/i)).toBeInTheDocument();
  });
});

describe("enforcement mode", () => {
  it("is shadow unless a valid, signed, active policy with legal signoff exists", () => {
    expect(enforcementMode(undefined).mode).toBe("unknown");
    expect(enforcementMode([]).mode).toBe("none");
    expect(enforcementMode([shadowPolicy]).mode).toBe("shadow");
    const active = { ...shadowPolicy, policy: { ...shadowPolicy.policy, mode: "active" as const, legal_signoff_ref: "LEGAL-1" } };
    expect(enforcementMode([active]).mode).toBe("active");
    expect(enforcementMode([{ ...active, policy: { ...active.policy, legal_signoff_ref: null } }]).mode).toBe("shadow");
    expect(enforcementMode([{ ...active, signature_valid: false }]).mode).toBe("none");
    expect(enforcementMode([{ ...active, valid_now: false }]).mode).toBe("none");
  });
});
