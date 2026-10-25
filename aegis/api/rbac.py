"""Role-based access control: one permission per capability, a fixed role matrix.

Separation of duties (spec sections 6, 9, 12):

* **viewer** reads findings, cases, evidence, graph, reports and ledger status;
* **analyst** works cases (triage, investigate, review, verify/reject), proposes
  actions and runs the deterministic simulation and authorization assessment.
  An analyst can never approve, deny, execute or roll back;
* **approver** approves or denies proposed actions and executes/rolls back
  authorized ones. Approval of one's own proposal is refused separately (four-eyes);
* **admin** configures the tenant (sources, signed IOC bundles, signed operator
  policies, topology) and reads the audit trail; admin is *not* an approver;
* **integration** (collectors) may only push telemetry.

Execution additionally always requires an allowed, policy-bound authorization
decision, a recorded human approval and a SAFE simulation: the role alone is
never sufficient.
"""
from __future__ import annotations

from enum import Enum

from aegis.api.auth import Principal, Role


class Permission(str, Enum):
    READ = "read"                         # findings, cases, evidence, graph, actions, reports
    READ_AUDIT = "read_audit"             # raw ledger entries, quarantine contents
    INGEST = "ingest"
    CASE_WORK = "case_work"               # transitions up to VERIFIED/REJECTED/INCONCLUSIVE/CLOSED
    INVESTIGATE = "investigate"
    PROPOSE = "propose"                   # propose, simulate, authorization assessment
    APPROVE = "approve"                   # approve / deny / expire
    EXECUTE = "execute"                   # execute / rollback
    CONFIGURE = "configure"               # sources, IOC bundles, policies, topology


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.READ}),
    Role.ANALYST: frozenset({Permission.READ, Permission.CASE_WORK, Permission.INVESTIGATE,
                             Permission.PROPOSE}),
    Role.APPROVER: frozenset({Permission.READ, Permission.APPROVE, Permission.EXECUTE}),
    Role.ADMIN: frozenset({Permission.READ, Permission.READ_AUDIT, Permission.CONFIGURE}),
    Role.INTEGRATION: frozenset({Permission.INGEST}),
}


def permissions_of(principal: Principal) -> frozenset[Permission]:
    out: set[Permission] = set()
    for role in principal.roles:
        out |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(out)


def allowed(principal: Principal, permission: Permission) -> bool:
    return permission in permissions_of(principal)


__all__ = ["Permission", "ROLE_PERMISSIONS", "allowed", "permissions_of"]
