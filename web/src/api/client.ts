import type {
  ActionDetail,
  ActionType,
  ApiErrorBody,
  AuthConfig,
  TokenResponse,
  AuthorizeResult,
  Case,
  CaseDetail,
  CaseState,
  DemoToken,
  EvidenceView,
  ExecutionRecord,
  Finding,
  GraphView,
  HistoryEntry,
  InvestigationReport,
  IocBundleStatus,
  LedgerEntry,
  LedgerVerify,
  ListOf,
  Me,
  MetricsSummary,
  MirrorResult,
  Page,
  PolicyItem,
  PovReport,
  ProposedAction,
  Replay,
  Role,
  SourceConfig,
  TopologyStatus,
} from "./types";

export const API_BASE = "/api/v1";

/** An API refusal or failure, carrying the server's stable error code and failed checks. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly failedChecks: string[];
  readonly requestId: string | null;
  readonly fieldErrors: Array<{ loc: string[]; msg: string }>;

  constructor(status: number, body: Partial<ApiErrorBody> | null, fallback: string) {
    super(body?.detail || fallback);
    this.name = "ApiError";
    this.status = status;
    this.code = body?.error || (status === 0 ? "network_error" : `http_${status}`);
    this.failedChecks = Array.isArray(body?.failed_checks) ? body!.failed_checks : [];
    this.requestId = body?.request_id ?? null;
    this.fieldErrors = Array.isArray(body?.errors)
      ? body!.errors.map((e) => ({ loc: e.loc, msg: e.msg }))
      : [];
  }
}

export type Query = Record<string, string | number | boolean | null | undefined>;

export function buildQuery(q?: Query): string {
  if (!q) return "";
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === "") continue;
    params.set(k, String(v));
  }
  const s = params.toString();
  return s ? `?${s}` : "";
}

export interface ClientOptions {
  getToken: () => string | null;
  onUnauthorized?: () => void;
  fetchImpl?: typeof fetch;
}

/** Thin typed wrapper over the AEGIS REST API. Every call carries the bearer token. */
export type OidcGrant =
  | { grant_type: "authorization_code"; code: string; code_verifier: string; redirect_uri: string }
  | { grant_type: "refresh_token"; refresh_token: string };

export class AegisClient {
  private readonly opts: ClientOptions;

  constructor(opts: ClientOptions) {
    this.opts = opts;
  }

  private async raw(method: string, path: string, init?: { query?: Query; body?: unknown; accept?: string }) {
    const headers: Record<string, string> = { Accept: init?.accept ?? "application/json" };
    const token = this.opts.getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    let body: string | undefined;
    if (init?.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(init.body);
    }
    const f = this.opts.fetchImpl ?? fetch;
    let res: Response;
    try {
      res = await f(`${API_BASE}${path}${buildQuery(init?.query)}`, { method, headers, body });
    } catch (exc) {
      throw new ApiError(0, null, `network error: ${(exc as Error).message || "unreachable"}`);
    }
    if (!res.ok) {
      let parsed: Partial<ApiErrorBody> | null = null;
      try {
        parsed = (await res.json()) as Partial<ApiErrorBody>;
      } catch {
        parsed = null;
      }
      const err = new ApiError(res.status, parsed, `${method} ${path} failed (${res.status})`);
      if (res.status === 401 && token) this.opts.onUnauthorized?.();
      throw err;
    }
    return res;
  }

  async get<T>(path: string, query?: Query): Promise<T> {
    const res = await this.raw("GET", path, { query });
    return (await res.json()) as T;
  }

  async post<T>(path: string, body?: unknown, query?: Query): Promise<T> {
    const res = await this.raw("POST", path, { body: body ?? {}, query });
    return (await res.json()) as T;
  }

  async text(path: string, query?: Query): Promise<string> {
    const res = await this.raw("GET", path, { query, accept: "text/html" });
    return res.text();
  }

  // ---------------------------------------------------------------- identity
  authConfig = () => this.get<AuthConfig>("/auth/config");
  demoToken = (role: Role) => this.get<DemoToken>("/demo/token", { role });
  me = () => this.get<Me>("/me");
  /** Relay an OIDC grant (authorization code + PKCE verifier, or refresh token) through the API. */
  oidcToken = (grant: OidcGrant) => this.post<TokenResponse>("/auth/token", grant);

  // ---------------------------------------------------------------- overview / configuration
  metrics = () => this.get<MetricsSummary>("/metrics/summary");
  policies = () => this.get<ListOf<PolicyItem>>("/policies");
  sources = () => this.get<ListOf<SourceConfig>>("/sources");
  iocs = () => this.get<{ bundle: IocBundleStatus | null }>("/iocs");
  topology = () => this.get<{ topology: TopologyStatus | null }>("/topology");

  // ---------------------------------------------------------------- findings and cases
  findings = (q: Query) => this.get<Page<Finding>>("/findings", q);
  finding = (id: string) => this.get<Finding>(`/findings/${encodeURIComponent(id)}`);
  cases = (q: Query) => this.get<Page<Case>>("/cases", q);
  caseDetail = (id: string) => this.get<CaseDetail>(`/cases/${encodeURIComponent(id)}`);
  caseEvidence = (id: string) => this.get<ListOf<EvidenceView>>(`/cases/${encodeURIComponent(id)}/evidence`);
  caseHistory = (id: string) => this.get<ListOf<HistoryEntry>>(`/cases/${encodeURIComponent(id)}/history`);
  caseInvestigation = (id: string) =>
    this.get<InvestigationReport>(`/cases/${encodeURIComponent(id)}/investigation`);
  caseReplay = (id: string, asOf?: string) =>
    this.get<Replay>(`/cases/${encodeURIComponent(id)}/replay`, { as_of: asOf });
  transition = (id: string, toState: CaseState, reason: string) =>
    this.post<Case>(`/cases/${encodeURIComponent(id)}/transition`, { to_state: toState, reason });
  review = (id: string, alternatives: string[], notes: string) =>
    this.post<Case>(`/cases/${encodeURIComponent(id)}/review`, { alternatives, notes });
  addNote = (id: string, note: string) => this.post<unknown>(`/cases/${encodeURIComponent(id)}/notes`, { note });
  investigate = (id: string) =>
    this.post<InvestigationReport>(`/cases/${encodeURIComponent(id)}/investigate`, undefined);
  evidence = (id: string) => this.get<EvidenceView>(`/evidence/${encodeURIComponent(id)}`);
  graph = (node: string, asOf?: string) =>
    this.get<GraphView>(`/graph/${node.split("/").map(encodeURIComponent).join("/")}`, { as_of: asOf });

  // ---------------------------------------------------------------- ledger
  ledgerVerify = () => this.get<LedgerVerify>("/ledger/verify");
  ledgerEntries = (q: Query) => this.get<Page<LedgerEntry>>("/ledger/entries", q);

  // ---------------------------------------------------------------- actions (MIRROR)
  actions = (q: Query) => this.get<Page<ProposedAction>>("/actions", q);
  action = (id: string) => this.get<ActionDetail>(`/actions/${encodeURIComponent(id)}`);
  propose = (body: ProposeBody) => this.post<ProposedAction>("/actions", body);
  simulate = (id: string) => this.post<MirrorResult>(`/actions/${encodeURIComponent(id)}/simulate`, undefined);
  authorize = (id: string, policyId?: string) =>
    this.post<AuthorizeResult>(`/actions/${encodeURIComponent(id)}/authorize`, policyId ? { policy_id: policyId } : {});
  approve = (id: string, reason: string) =>
    this.post<{ case: Case }>(`/actions/${encodeURIComponent(id)}/approve`, { reason });
  deny = (id: string, reason: string) =>
    this.post<{ case: Case }>(`/actions/${encodeURIComponent(id)}/deny`, { reason });
  execute = (id: string, reason: string) =>
    this.post<{ execution: ExecutionRecord; case_state: CaseState }>(
      `/actions/${encodeURIComponent(id)}/execute`,
      { reason },
    );
  rollback = (id: string, reason: string) =>
    this.post<{ execution: ExecutionRecord; case_state: CaseState }>(
      `/actions/${encodeURIComponent(id)}/rollback`,
      { reason },
    );

  // ---------------------------------------------------------------- reports
  povJson = (q: Query) => this.get<PovReport>("/reports/pov", { ...q, format: "json" });
  povHtml = (q: Query) => this.text("/reports/pov", { ...q, format: "html" });
}

export interface ProposeBody {
  case_id: string;
  action_type: ActionType;
  targets: string[];
  scope?: Record<string, unknown>;
  legal_basis?: string | null;
  expires_in_hours?: number;
  rollback_plan?: string | null;
}

/** One-line human message for an error, including failed checks when the server named them. */
export function describeError(err: unknown): string {
  if (err instanceof ApiError) {
    const parts = [err.message];
    if (err.fieldErrors.length) parts.push(err.fieldErrors.map((e) => `${e.loc.slice(1).join(".")}: ${e.msg}`).join("; "));
    if (err.failedChecks.length) parts.push(`failed checks: ${err.failedChecks.join(", ")}`);
    return parts.join(" — ");
  }
  if (err instanceof Error) return err.message;
  return String(err);
}
