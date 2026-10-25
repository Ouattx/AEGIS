"""Service-level safety controls added for spec section 15: key revocation, legitimate-traffic
health reports (circuit-breaker rollback) and gated model activation."""
from __future__ import annotations

import pytest

from aegis.provenance.ledger import EntryType
from aegis.provenance.signing import Signer
from aegis.sentinel.model import load_default
from aegis.service import AegisService, ConflictError, InvalidInputError, NotFoundError

from test_api_helpers import make_service, operator_signer, seed_case, signed_policy

T = "isp-a"


@pytest.fixture()
def svc(tmp_path):
    s = make_service(tmp_path)
    yield s
    s.close()


def test_revoke_key_validation(svc: AegisService) -> None:
    with pytest.raises(InvalidInputError):
        svc.revoke_key("bogus", "k", actor="a", reason="r")  # type: ignore[arg-type]
    with pytest.raises(InvalidInputError):
        svc.revoke_key("policy", "../etc", actor="a", reason="r")
    with pytest.raises(InvalidInputError):
        svc.revoke_key("policy", "k1", actor="a", reason="  ")
    with pytest.raises(ConflictError) as ei:
        svc.revoke_key("ledger", svc.ledger_signer.key_id, actor="a", reason="r")
    assert ei.value.failed == ["active_ledger_key"]


def test_revocation_is_immediate_persistent_and_ledgered(svc: AegisService, tmp_path) -> None:
    seed_case(svc, T)  # gives the tenant a ledger
    signer = operator_signer(svc, "op-key")
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    assert svc.list_policies(T)[0]["signature_valid"] is True
    out = svc.revoke_key("policy", "op-key", actor="secops", reason="leaked")
    svc.revoke_key("policy", "op-key", actor="secops", reason="leaked again")  # idempotent on disk
    assert out["revoked"] == ["op-key"] and out["ioc_bundles_deactivated"] == []
    assert svc.list_policies(T)[0]["signature_valid"] is False
    lines = (svc.settings.trusted_dir / "policy" / "revoked.txt").read_text().splitlines()
    assert len(lines) == 1 and lines[0].startswith("op-key")
    events = [e.payload for e in svc.ledger.entries(T, entry_type="configuration")
              if e.payload.get("event") == "key_revoked"]
    assert len(events) == 2 and events[0]["key_id"] == "op-key"
    with pytest.raises(InvalidInputError):
        svc.trust_key("policy", "op-key", signer.public_pem())
    # a restart honors the revocation although the public key file is still trusted on disk
    assert (svc.settings.trusted_dir / "policy" / "op-key.pem").is_file()
    svc.close()
    again = AegisService(svc.settings, load_default_model=False, use_env_llm=False)
    try:
        assert again.policy_keyring.is_revoked("op-key") and "op-key" not in again.policy_keyring.key_ids()
        assert again.list_policies(T)[0]["signature_valid"] is False
    finally:
        again.close()


def test_revocation_file_ignores_comments_and_garbage(svc: AegisService) -> None:
    path = svc.settings.trusted_dir / "ioc" / "revoked.txt"
    path.write_text("# comment line\nfeed-key  # why\n\n../bad id\n")
    assert svc._revoked_key_ids("ioc") == {"feed-key"}
    other = Signer.generate("feed-key")
    svc.reload_trusted_keys()  # applies the file before any public key is trusted
    assert svc.ioc_keyring.is_revoked("feed-key")
    with pytest.raises(InvalidInputError):
        svc.trust_key("ioc", "feed-key", other.public_pem())


def test_report_legit_traffic_requires_live_action(svc: AegisService) -> None:
    with pytest.raises(NotFoundError):
        svc.report_legit_traffic(T, "no-such-action", requests=10, errors=0)


def test_activate_model_swaps_every_sentinel_and_is_ledgered(svc: AegisService) -> None:
    seed_case(svc, T)
    before = svc.detector_version(T)
    assert "nomodel" in before
    with pytest.raises(InvalidInputError):
        svc.activate_model(None, actor="ops", reason=" ")
    model = load_default()
    svc.activate_model(model, actor="ml.release", reason="gated promotion")
    assert svc.model is model and model.model_id in svc.detector_version(T)
    entry = svc.ledger.entries(T, entry_type=EntryType.MODEL)[-1].payload
    assert entry["model_id"] == model.model_id and entry["previous_model_id"] is None
    svc.activate_model(None, actor="ml.release", reason="withdraw model")
    assert "nomodel" in svc.detector_version(T)
