#!/usr/bin/env node
/*
 * End-to-end smoke test of the AEGIS console against a running API (e.g. `aegis demo`).
 *
 *   AEGIS_URL=http://127.0.0.1:8000 node scripts/smoke.cjs [--screenshots ../docs/screenshots]
 *
 * Walks the full analyst -> approver workflow in a real Chromium:
 *   role-picker login, overview KPIs, findings + drawer, case review and verification,
 *   evidence trail, graph neighbourhood, replay-as-of, propose -> MIRROR simulation ->
 *   authorization checklist (shadow policy refuses), approver sees approval blocked and
 *   denies, admin verifies the ledger, viewer generates and opens the PoV report.
 * Fails on any page error, console error or 5xx response.
 *
 * Uses the preinstalled `playwright` package (resolved from NODE_PATH); it does not
 * download browsers.
 */
"use strict";
const path = require("path");
const fs = require("fs");
const { chromium } = require("playwright");

const BASE = (process.env.AEGIS_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
const argIdx = process.argv.indexOf("--screenshots");
const SHOTS = argIdx > 0 ? path.resolve(process.argv[argIdx + 1]) : null;
const HEADED = process.argv.includes("--headed");

const problems = [];
let step = 0;

function log(msg) {
  step += 1;
  console.log(`[smoke ${String(step).padStart(2, "0")}] ${msg}`);
}

async function api(pathname, token) {
  const res = await fetch(`${BASE}/api/v1${pathname}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!res.ok) throw new Error(`${pathname} -> ${res.status}`);
  return res.json();
}

async function shot(page, name) {
  if (!SHOTS) return;
  fs.mkdirSync(SHOTS, { recursive: true });
  await page.mouse.move(2, 2);
  // hide transient toasts for the capture without touching React-managed nodes
  await page.evaluate(() => document.querySelectorAll(".toasts").forEach((t) => (t.style.visibility = "hidden")));
  await page.waitForTimeout(350);
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: false });
  await page.evaluate(() => document.querySelectorAll(".toasts").forEach((t) => (t.style.visibility = "")));
  console.log(`           screenshot ${name}.png`);
}

async function login(page, role) {
  await page.goto(`${BASE}/login`);
  const logout = page.getByTestId("logout");
  if (await logout.count()) {
    await logout.click();
  }
  await page.getByTestId(`role-${role}`).click();
  await page.getByTestId("user-chip").waitFor();
  await page.getByText(`demo-${role}`).first().waitFor();
}

async function reason(page, text) {
  await page.getByTestId("reason-input").fill(text);
  await page.getByTestId("reason-confirm").click();
}

async function main() {
  const cfg = await api("/auth/config");
  if (!cfg.demo) throw new Error("the API is not in demo mode (run `aegis demo`)");

  // choose an INVESTIGATING case the evidence guard allows to verify
  const analystToken = (await api("/demo/token?role=analyst")).access_token;
  const open = await api("/cases?state=INVESTIGATING&limit=50", analystToken);
  let caseId = null;
  for (const c of open.items) {
    const d = await api(`/cases/${c.case_id}`, analystToken);
    if (d.evidence_assessment.verification_blockers.length === 0) {
      caseId = c.case_id;
      break;
    }
  }
  if (!caseId) throw new Error("no verifiable INVESTIGATING case in the demo tenant (re-run `aegis demo`)");

  const browser = await chromium.launch({ headless: !HEADED });
  const context = await browser.newContext({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  page.on("pageerror", (e) => problems.push(`page error: ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error" && !/status of (401|403|404|409|422)/.test(m.text())) problems.push(`console error: ${m.text()}`);
  });
  page.on("response", (r) => {
    if (r.status() >= 500) problems.push(`HTTP ${r.status()} ${r.url()}`);
  });
  page.setDefaultTimeout(20_000);

  try {
    log("login screen and role picker");
    await page.goto(`${BASE}/`);
    await page.waitForURL(/\/login/);
    await page.getByTestId("role-analyst").waitFor();

    log("sign in as analyst, overview KPIs");
    await login(page, "analyst");
    await page.getByTestId("kpi-devices").waitFor();
    await page.getByTestId("mode-pill").getByText("Shadow mode").waitFor();
    await page.getByTestId("ledger-pill").getByText(/Ledger verified/).waitFor();
    await page.getByTestId("kpi-false-alerts").getByText(/upper bound/).waitFor();
    await page.locator("[data-testid=trend] svg rect").first().waitFor();
    await shot(page, "01-overview");

    log("findings list, filter, detail drawer");
    await page.getByTestId("nav-findings").click();
    await page.getByTestId("findings-table").waitFor();
    await page.getByTestId("filter-verdict").selectOption("malicious");
    await page.waitForURL(/verdict=malicious/);
    await page.locator("[data-testid=findings-table] tbody tr").first().click();
    await page.getByText("Fusion components").waitFor();
    await shot(page, "02-findings");
    await page.keyboard.press("Escape");

    log(`open case ${caseId.slice(0, 8)}, record counter-hypothesis review`);
    await page.goto(`${BASE}/cases/${caseId}`);
    await page.getByTestId("hypothesis").waitFor();
    await page.getByTestId("btn-review").click();
    await page.getByTestId("review-notes").fill("Destination is not a push/CDN provider, interval does not match the device-class baseline, indicator signed by an independent feed.");
    await page.getByTestId("review-submit").click();
    await page.getByTestId("hypothesis").getByText(/review recorded/).waitFor();

    log("verify the case (state machine guard passes)");
    await page.getByTestId("transition-VERIFIED").click();
    await reason(page, "Two independent origins and signed IOC hit; benign alternatives ruled out.");
    await page.getByTestId("btn-propose").waitFor();

    log("evidence trail with hashes and independence groups");
    await page.getByTestId("tab-evidence").click();
    await page.getByTestId("evidence-table").waitFor();
    await page.getByText("Source-independence groups").waitFor();
    await shot(page, "03-case-evidence");

    log("decision timeline");
    await page.getByTestId("tab-timeline").click();
    await page.getByTestId("timeline").getByText("INVESTIGATING → VERIFIED").waitFor();

    log("investigation report");
    await page.getByTestId("tab-investigation").click();
    await page.getByTestId("investigation").waitFor();

    log("graph neighbourhood");
    await page.getByTestId("tab-graph").click();
    await page.locator("[data-testid=graph-canvas] circle").first().waitFor();
    await shot(page, "04-case-graph");

    log("replay as of an earlier time");
    await page.getByTestId("tab-replay").click();
    await page.getByTestId("replay").getByText("Snapshot anchor").waitFor();
    await page.getByTestId("replay").getByRole("button", { name: "1", exact: true }).click();
    await page.getByTestId("replay").getByText("Case at T").waitFor();

    log("propose a DNS sinkhole");
    await page.getByTestId("tab-summary").click();
    await page.getByTestId("btn-propose").click();
    await page.getByTestId("propose-rollback-verified").check();
    const targets = await page.getByTestId("propose-targets").inputValue();
    if (!targets.trim()) await page.getByTestId("propose-targets").fill("cfg.boxhelper.example");
    await page.getByTestId("propose-submit").click();
    await page.getByTestId("action-detail").waitFor();
    const actionUrl = page.url();

    log("MIRROR simulation with collateral impact");
    await page.getByTestId("btn-simulate").click();
    await page.getByTestId("mirror-panel").getByText("Affected entities", { exact: true }).waitFor();

    log("deterministic authorization checklist (shadow policy refuses)");
    await page.getByTestId("btn-authorize").click();
    await page.getByTestId("authz-panel").getByText("not allowed", { exact: true }).waitFor();
    await page.getByTestId("authz-panel").getByText("policy_not_active_mode").first().waitFor();
    await shot(page, "05-action-authorization");

    log("approver: approval blocked by authorization, deny with reason");
    await login(page, "approver");
    await page.goto(actionUrl);
    await page.getByTestId("approval-panel").waitFor();
    if (await page.getByTestId("btn-approve").isEnabled()) throw new Error("approve should be disabled when authorization is not allowed");
    await page.getByTestId("btn-deny").click();
    await reason(page, "Shadow pilot: enforcement not authorized by operator policy.");
    await page.getByText("approval").first().waitFor();
    await page.locator("[data-testid=stepper] .step.blocked").getByText("Human approval").waitFor();

    log("admin: ledger verification and raw entries");
    await login(page, "admin");
    await page.getByTestId("nav-ledger").click();
    await page.getByTestId("ledger-verify").getByText("Chain verified").waitFor();
    await page.getByTestId("ledger-table").waitFor();
    await page.getByTestId("btn-verify").click();
    await page.getByTestId("ledger-verify").getByText("Chain verified").waitFor();

    log("settings: shadow policy in force");
    await page.getByTestId("nav-settings").click();
    await page.getByTestId("policy-panel").getByText("Shadow mode is in force.").waitFor();

    log("viewer: generate and open the proof-of-value report");
    await login(page, "viewer");
    await page.getByTestId("nav-reports").click();
    await page.getByTestId("btn-generate").click();
    await page.getByTestId("report-summary").waitFor();
    await page.getByTestId("btn-open-report").click();
    const frame = page.frameLocator("[data-testid=report-frame]");
    await frame.locator("body").waitFor();
    await page.waitForTimeout(500);
    await shot(page, "06-pov-report");
  } finally {
    await browser.close();
  }

  if (problems.length) {
    console.error(`\nSMOKE FAILED: ${problems.length} problem(s)`);
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(1);
  }
  console.log(`\nSMOKE PASSED (${step} steps)`);
}

main().catch((e) => {
  console.error(`\nSMOKE FAILED: ${e && e.stack ? e.stack : e}`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
});
