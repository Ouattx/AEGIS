"""Static checks of the shipped deployment artifacts against the code they deploy.

These tests keep the Dockerfile, compose files, environment template, Prometheus rules,
Grafana dashboard and CI workflows consistent with the application (settings, metrics,
CLI) and with the hardening the security documentation promises.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

from aegis.api.metrics import ApiMetrics, _Metric
from aegis.api.settings import ENV_VARS, Settings
from aegis.cli import build_parser

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"

#: settings intentionally not configurable through deploy/.env (dev/demo only, or fixed by the image/compose)
NOT_IN_PRODUCTION_ENV = {"AEGIS_DEMO_TENANT", "AEGIS_DEV_JWT_SECRET", "AEGIS_DEV_TOKEN_TTL_S", "AEGIS_WEB_DIST",
                         "AEGIS_MODEL_DIR"}


def _yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    return _yaml(DEPLOY / "docker-compose.yml")


@pytest.fixture(scope="module")
def env_example() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (DEPLOY / ".env.example").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _anchors(doc: Path) -> set[str]:
    """GitHub-style heading anchors of a Markdown file."""
    out = set()
    for heading in re.findall(r"^#{1,6}\s+(.+?)\s*$", doc.read_text(encoding="utf-8"), re.M):
        slug = re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")
        out.add(slug)
    return out


def _metric_names() -> dict[str, tuple[str, tuple[str, ...]]]:
    """name -> (kind, labelnames) for everything ApiMetrics exports, histogram series included."""
    m = ApiMetrics("test")
    out: dict[str, tuple[str, tuple[str, ...]]] = {}
    for obj in vars(m).values():
        if isinstance(obj, _Metric):
            out[obj.name] = (obj.kind, obj.labelnames)
            if obj.kind == "histogram":
                for suffix, extra in (("_bucket", ("le",)), ("_sum", ()), ("_count", ())):
                    out[obj.name + suffix] = ("histogram_series", obj.labelnames + extra)
    return out


# ============================================================================ Dockerfile


def test_dockerfile_is_multistage_non_root_with_healthcheck():
    text = (ROOT / "Dockerfile").read_text()
    stages = re.findall(r"^FROM\s+(\S+)\s+AS\s+(\w+)", text, re.M)
    assert [s[1] for s in stages] == ["web", "builder", "runtime"]
    runtime = text[text.index("AS runtime"):]
    user = re.findall(r"^USER\s+(\S+)", runtime, re.M)
    assert user and user[-1].split(":")[0] not in ("0", "root")
    assert re.search(r"^HEALTHCHECK ", runtime, re.M)
    assert "apt-get" not in runtime and "pip install" not in runtime  # no package manager in the final stage
    assert "slim" in stages[2][0]
    assert not re.search(r"^ADD\s+https?://", text, re.M)
    # artifacts the runtime copies exist in the repository
    for src in re.findall(r"^COPY\s+(?!--from)(\S+)\s+", text, re.M):
        assert (ROOT / src.rstrip("/")).exists(), src
    assert 'ENTRYPOINT ["aegis"]' in text


def test_dockerfile_env_points_at_copied_artifacts():
    text = (ROOT / "Dockerfile").read_text()
    assert "AEGIS_WEB_DIST=/opt/aegis/web/dist" in text and "COPY --from=web /src/web/dist /opt/aegis/web/dist" in text
    assert "AEGIS_MODEL_DIR=/opt/aegis/models/sentinel-default" in text
    assert (ROOT / "models" / "sentinel-default" / "manifest.json").is_file()
    assert "COPY deploy/tools /opt/aegis/tools" in text


def test_dockerignore_excludes_secrets_and_local_state_but_keeps_tools():
    lines = [ln.strip() for ln in (ROOT / ".dockerignore").read_text().splitlines()
             if ln.strip() and not ln.startswith("#")]
    for must in (".git", ".env", "*.pem", "*.key", "keys/", "web/node_modules", "backups", "deploy"):
        assert must in lines, must
    assert "!deploy/tools" in lines
    assert lines.index("!deploy/tools") > lines.index("deploy")


# ============================================================================ compose


def test_compose_api_is_hardened_and_bound_locally(compose):
    api = compose["services"]["api"]
    assert api["read_only"] is True
    assert api["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in api["security_opt"]
    assert api["init"] is True
    assert any(t.startswith("/tmp") for t in api["tmpfs"])
    assert api["ports"] == ["${AEGIS_BIND:-127.0.0.1}:${AEGIS_PORT:-8000}:8000"]
    assert api["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert "env_file" not in api  # explicit allow-list only
    assert api["volumes"] == ["aegis-data:/var/lib/aegis"]


def test_compose_database_is_internal_and_unpublished(compose):
    pg = compose["services"]["postgres"]
    assert "ports" not in pg
    assert pg["networks"] == ["backend"]
    assert compose["networks"]["backend"]["internal"] is True
    assert pg["environment"]["POSTGRES_PASSWORD"].startswith("${POSTGRES_PASSWORD:?")
    assert "scram-sha-256" in pg["environment"]["POSTGRES_INITDB_ARGS"]


def test_compose_profiles(compose):
    services = compose["services"]
    assert "profiles" not in services["api"] and "profiles" not in services["postgres"]
    assert services["prometheus"]["profiles"] == ["monitoring"]
    assert services["grafana"]["profiles"] == ["monitoring"]
    assert services["redpanda"]["profiles"] == ["bus"]
    for name in ("prometheus", "grafana", "redpanda"):
        for port in services[name]["ports"]:
            assert port.startswith("${") and "127.0.0.1" in port, (name, port)


def test_compose_api_environment_covers_every_setting(compose):
    env = compose["services"]["api"]["environment"]
    expected = set(ENV_VARS.values()) - NOT_IN_PRODUCTION_ENV
    assert expected <= set(env), sorted(expected - set(env))
    # read outside Settings: the uvicorn launcher, the LLM client and the pseudonymization key provider
    read_elsewhere = {"AEGIS_FORWARDED_ALLOW_IPS", "AEGIS_LLM_MODEL", "AEGIS_PSEUDONYM_MASTER_KEY"}
    unknown = {k for k in env if k.startswith("AEGIS_")} - set(ENV_VARS.values()) - read_elsewhere
    assert not unknown
    # secure defaults when deploy/.env leaves a value empty
    assert env["AEGIS_ENV"] == "${AEGIS_ENV:-production}"
    assert env["AEGIS_AUTH_MODE"] == "${AEGIS_AUTH_MODE:-oidc}"
    assert env["AEGIS_ENFORCEMENT_ADAPTER"] == "${AEGIS_ENFORCEMENT_ADAPTER:-dryrun}"
    assert env["AEGIS_LLM_ENABLED"] == "${AEGIS_LLM_ENABLED:-false}"
    for required in ("AEGIS_PSEUDONYM_MASTER_KEY", "AEGIS_METRICS_TOKEN"):
        assert env[required].startswith(f"${{{required}:?"), required
    assert env["AEGIS_DATABASE_URL"].startswith("postgresql+psycopg://")
    assert "GRAFANA_ADMIN_PASSWORD" not in json.dumps(env)


def test_every_compose_variable_is_documented_in_env_example(compose, env_example):
    text = (DEPLOY / "docker-compose.yml").read_text()
    referenced = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", text))
    optional_image_overrides = {"POSTGRES_IMAGE", "PROMETHEUS_IMAGE", "GRAFANA_IMAGE", "REDPANDA_IMAGE"}
    missing = referenced - set(env_example) - optional_image_overrides
    assert not missing, sorted(missing)


def test_env_example_has_secure_defaults_and_no_secrets(env_example):
    assert env_example["AEGIS_ENV"] == "production"
    assert env_example["AEGIS_AUTH_MODE"] == "oidc"
    assert env_example["AEGIS_ENFORCEMENT_ADAPTER"] == "dryrun"
    assert env_example["AEGIS_LLM_ENABLED"] == "false"
    assert env_example["AEGIS_BIND"] == "127.0.0.1"
    for secret in ("POSTGRES_PASSWORD", "AEGIS_PSEUDONYM_MASTER_KEY", "AEGIS_METRICS_TOKEN", "GRAFANA_ADMIN_PASSWORD",
                   "AEGIS_WEBHOOK_SECRET", "ANTHROPIC_API_KEY", "AEGIS_OIDC_ISSUER"):
        assert env_example[secret] == "", f"{secret} must ship empty"


def test_env_example_filled_in_is_a_valid_production_configuration(env_example):
    """The template plus the REQUIRED values yields settings the API accepts in production."""
    environ = {k: v for k, v in env_example.items() if k.startswith("AEGIS_")}
    environ.update({"AEGIS_OIDC_ISSUER": "https://sso.operator.example/realms/soc",
                    "AEGIS_PSEUDONYM_MASTER_KEY": "ab" * 32, "AEGIS_METRICS_TOKEN": "t" * 32})
    s = Settings.from_env(environ)
    assert s.is_production and s.auth_mode == "oidc" and s.enforcement_adapter == "dryrun"
    assert s.llm_enabled is False and s.oidc_audience == "aegis-api"
    assert s.max_ingest_bytes == 64 * 1024 * 1024


def test_env_example_without_oidc_issuer_is_refused(env_example):
    environ = {k: v for k, v in env_example.items() if k.startswith("AEGIS_")}
    with pytest.raises(ValueError, match="AEGIS_OIDC_ISSUER"):
        Settings.from_env(environ)


def test_demo_compose_is_local_only_and_hardened():
    demo = _yaml(DEPLOY / "docker-compose.demo.yml")["services"]["demo"]
    assert demo["ports"] == ["127.0.0.1:${DEMO_PORT:-8080}:8000"]
    assert demo["read_only"] is True and demo["cap_drop"] == ["ALL"]
    assert demo["command"][0] == "demo"
    sub = {a.dest: a for a in build_parser()._subparsers._group_actions}["cmd"].choices  # type: ignore[union-attr]
    demo_flags = {o for a in sub["demo"]._actions for o in a.option_strings}
    assert {f for f in demo["command"] if f.startswith("--")} <= demo_flags


def test_compose_api_command_is_a_valid_cli_invocation(compose):
    cmd = compose["services"]["api"]["command"]
    args = build_parser().parse_args(cmd)
    assert args.cmd == "serve" and args.host == "0.0.0.0" and args.port == 8000


# ============================================================================ Prometheus


def test_prometheus_scrapes_api_with_bearer_token_file():
    cfg = _yaml(DEPLOY / "prometheus" / "prometheus.yml")
    job = next(j for j in cfg["scrape_configs"] if j["job_name"] == "aegis-api")
    assert job["static_configs"][0]["targets"] == ["api:8000"]
    assert job["authorization"]["credentials_file"] == "/tmp/aegis_metrics_token"
    assert cfg["rule_files"] == ["/etc/prometheus/rules/*.yml"]
    compose_text = (DEPLOY / "docker-compose.yml").read_text()
    assert "/tmp/aegis_metrics_token" in compose_text


def _rule_exprs() -> list[tuple[str, str]]:
    rules = _yaml(DEPLOY / "prometheus" / "rules" / "aegis-alerts.yml")
    out = []
    for g in rules["groups"]:
        for r in g["rules"]:
            out.append((r.get("alert") or r.get("record"), r["expr"]))
    return out


def _used_metrics(expr: str) -> set[str]:
    return set(re.findall(r"\b(aegis_[a-z_]+)\b", expr))


def test_alert_rules_reference_only_exported_metrics_and_labels():
    known = _metric_names()
    for name, expr in _rule_exprs():
        for metric in _used_metrics(expr):
            assert metric in known, f"{name}: unknown metric {metric}"
        for metric, labels in re.findall(r"\b(aegis_[a-z_]+)\{([^}]*)\}", expr):
            for label in re.findall(r"(\w+)\s*(?:=~|!~|!=|=)", labels):
                assert label in known[metric][1], f"{name}: {metric} has no label {label}"


def test_alert_rules_have_severity_and_existing_runbooks():
    rules = _yaml(DEPLOY / "prometheus" / "rules" / "aegis-alerts.yml")
    alerts = [r for g in rules["groups"] for r in g["rules"] if "alert" in r]
    assert len(alerts) >= 10
    for a in alerts:
        assert a["labels"]["severity"] in ("page", "ticket"), a["alert"]
        path, _, anchor = a["annotations"]["runbook"].partition("#")
        doc = ROOT / path
        assert doc.is_file(), a["annotations"]["runbook"]
        if anchor:
            assert anchor in _anchors(doc), f"{a['alert']}: no heading #{anchor} in {path}"


def test_route_labels_in_rules_match_real_api_routes():
    from aegis.api.routes import router
    paths = {getattr(r, "path", "") for r in router.routes}
    for name, expr in _rule_exprs():
        for route in re.findall(r'route="([^"]+)"', expr):
            assert route in paths, f"{name}: no API route {route}"


def test_promtool_unit_tests_cover_safety_alerts():
    tests = _yaml(DEPLOY / "prometheus" / "tests" / "aegis-alerts.test.yml")
    assert tests["rule_files"] == ["../rules/aegis-alerts.yml"]
    covered = {t["alertname"] for case in tests["tests"] for t in case.get("alert_rule_test", [])}
    assert {"AegisEnforcementApplied", "AegisAuditWriteFailure", "AegisNotReady", "AegisRollbackFailed",
            "AegisIngestValidRatioLow"} <= covered


# ============================================================================ Grafana


def test_grafana_provisioning_matches_dashboard():
    ds = _yaml(DEPLOY / "grafana" / "provisioning" / "datasources" / "prometheus.yml")["datasources"][0]
    assert ds["uid"] == "aegis-prometheus" and ds["url"] == "http://prometheus:9090"
    prov = _yaml(DEPLOY / "grafana" / "provisioning" / "dashboards" / "aegis.yml")["providers"][0]
    assert prov["options"]["path"] == "/var/lib/grafana/dashboards"
    assert prov["allowUiUpdates"] is False


def test_grafana_dashboard_is_valid_and_uses_exported_metrics():
    dash = json.loads((DEPLOY / "grafana" / "dashboards" / "aegis-shield.json").read_text())
    assert dash["uid"] == "aegis-shield-ops"
    panels = dash["panels"]
    ids = [p["id"] for p in panels]
    assert len(ids) == len(set(ids))
    known = _metric_names()
    data_panels = [p for p in panels if p["type"] != "row"]
    assert len(data_panels) >= 20
    for p in data_panels:
        assert p["datasource"]["uid"] == "aegis-prometheus"
        assert p["targets"], p["title"]
        g = p["gridPos"]
        assert 0 <= g["x"] and g["x"] + g["w"] <= 24, p["title"]
        for t in p["targets"]:
            for metric in _used_metrics(t["expr"]):
                assert metric in known, f"{p['title']}: unknown metric {metric}"
    titles = {p["title"] for p in data_panels}
    assert "Live enforcement applied (range)" in titles and "Audit write failures (range)" in titles


def test_grafana_dashboard_panels_do_not_overlap():
    dash = json.loads((DEPLOY / "grafana" / "dashboards" / "aegis-shield.json").read_text())
    cells: set[tuple[int, int]] = set()
    for p in dash["panels"]:
        g = p["gridPos"]
        for x in range(g["x"], g["x"] + g["w"]):
            for y in range(g["y"], g["y"] + g["h"]):
                assert (x, y) not in cells, p["title"]
                cells.add((x, y))


# ============================================================================ scripts, examples, Makefile


@pytest.mark.parametrize("script", ["smoke-test.sh", "backup.sh", "restore.sh", "purge-expired.sh"])
def test_shell_scripts_are_strict_and_executable(script):
    path = DEPLOY / script
    text = path.read_text()
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    assert os.stat(path).st_mode & stat.S_IXUSR


def test_purge_targets_only_expired_quarantine():
    text = (DEPLOY / "purge-expired.sh").read_text()
    deletes = re.findall(r"DELETE FROM (\w+)\s+WHERE kind = '(\w+)'", text)
    assert deletes == [("docs", "Quarantined")]
    assert "retention_until" in text
    from aegis.ingest.validator import Quarantined
    assert "retention_until" in Quarantined.model_fields
    assert Quarantined.__name__ == "Quarantined"  # DocStore kind is the class name


def test_restore_refuses_on_checksum_mismatch_and_asks_confirmation():
    text = (DEPLOY / "restore.sh").read_text()
    assert "sha256sum -c SHA256SUMS" in text
    assert "ASSUME_YES" in text and "Type 'restore' to continue" in text


def test_example_policy_and_topology_are_accepted_by_the_code():
    from aegis.api.topology import parse_topology
    from aegis.contracts.models import OperatorPolicy
    policy = OperatorPolicy.model_validate(json.loads((DEPLOY / "examples" / "operator-policy.shadow.json").read_text()))
    assert policy.mode == "shadow" and policy.legal_signoff_ref is None
    topo = parse_topology(json.loads((DEPLOY / "examples" / "topology.example.json").read_text()))
    assert topo.summary()["hosts"] == 4 and topo.complete is False


def test_example_policy_signs_with_the_cli_and_verifies(tmp_path, capsys):
    from aegis.cli import main
    from aegis.contracts.models import OperatorPolicy
    from aegis.provenance.signing import KeyRing, verify_model
    assert main(["keys", "generate", "--key-id", "acme-policy-2026", "--out-dir", str(tmp_path)]) == 0
    out = tmp_path / "signed.json"
    assert main(["policy", "sign", str(DEPLOY / "examples" / "operator-policy.shadow.json"),
                 "--key", str(tmp_path / "acme-policy-2026.key.pem"), "--key-id", "acme-policy-2026",
                 "--out", str(out)]) == 0
    capsys.readouterr()
    ring = KeyRing()
    ring.add("acme-policy-2026", (tmp_path / "acme-policy-2026.pem").read_bytes())
    assert verify_model(OperatorPolicy.model_validate(json.loads(out.read_text())), ring)


def test_makefile_targets_referenced_in_docs_exist():
    targets = set(re.findall(r"^([a-zA-Z0-9_.-]+):", (ROOT / "Makefile").read_text(), re.M))
    docs = [ROOT / "README.md", *(ROOT / "docs" / n for n in ("INSTALL.md", "CONFIGURATION.md", "SLO.md")),
            *sorted((ROOT / "docs" / "runbooks").glob("*.md"))]
    for doc in docs:
        for target in re.findall(r"`make ([a-z0-9-]+)", doc.read_text()):
            assert target in targets, f"{doc.name}: make {target}"
    phony = set(re.findall(r"^\.PHONY: (\S+)", (ROOT / "Makefile").read_text(), re.M))
    assert {"lint", "test", "image", "smoke", "sbom", "audit", "backup"} <= phony


# ============================================================================ CI


@pytest.fixture(scope="module")
def ci() -> dict[str, Any]:
    return _yaml(ROOT / ".github" / "workflows" / "ci.yml")


def test_ci_has_every_required_gate(ci):
    jobs = ci["jobs"]
    assert {"lint", "test", "web", "audit", "sbom", "deploy", "container"} <= set(jobs)
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    for needle in ("ruff check", "pytest -q -m safety", "pip-audit", "npm audit --omit=dev --audit-level=high",
                   "cyclonedx-py environment", "npm sbom", "anchore/sbom-action", "promtool test rules",
                   "deploy/smoke-test.sh", "shellcheck", "npm run build", "npm test"):
        assert needle in text, needle
    assert ci["permissions"] == {"contents": "read"}
    assert jobs["test"]["env"]["AEGIS_TEST_POSTGRES_URL"].startswith("postgresql+psycopg://")


def test_ci_ruff_version_matches_the_lint_configuration(ci):
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "[tool.ruff.lint]" in pyproject
    steps = ci["jobs"]["lint"]["steps"]
    assert any("ruff==" in str(s.get("run", "")) for s in steps)


def test_release_workflow_signs_and_attests(ci):
    rel = _yaml(ROOT / ".github" / "workflows" / "release.yml")
    # PyYAML reads the bare `on` key as boolean True
    trigger = rel.get("on", rel.get(True))
    assert trigger == {"push": {"tags": ["v*.*.*"]}}
    perms = rel["jobs"]["image"]["permissions"]
    assert perms["id-token"] == "write" and perms["packages"] == "write"
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "cosign sign --yes" in text and "cosign attest --yes --type cyclonedx" in text
    assert "actions/attest-build-provenance" in text


def test_workflow_actions_are_version_pinned():
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        for ref in re.findall(r"uses:\s*(\S+)", wf.read_text()):
            assert "@" in ref and not ref.endswith(("@main", "@master", "@latest")), f"{wf.name}: {ref}"
