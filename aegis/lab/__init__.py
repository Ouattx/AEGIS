"""AEGIS lab: deterministic synthetic corpus, hosting topology and signed IOC bundle
for offline evaluation (spec sections 1 and 7). Nothing here touches a real network:
all addresses and names come from reserved documentation/benchmark ranges."""
from aegis.lab.corpus import (
    BENIGN,
    DEFAULT_START,
    LAB_AUTHORIZATION_ID,
    Corpus,
    DeviceDayLabel,
    DeviceSpec,
    generate_corpus,
    lab_sources,
    lab_tenant_key,
)
from aegis.lab.iocs import BUNDLE_SCHEMA, build_ioc_bundle, bundle_signing_bytes, lab_signer, sign_bundle, verify_bundle
from aegis.lab.topology import Endpoint, HostingTopology, HostRecord, MaliciousInfra, generate_topology

__all__ = [
    "BENIGN", "DEFAULT_START", "LAB_AUTHORIZATION_ID", "Corpus", "DeviceDayLabel", "DeviceSpec",
    "generate_corpus", "lab_sources", "lab_tenant_key", "BUNDLE_SCHEMA", "build_ioc_bundle", "bundle_signing_bytes", "lab_signer",
    "sign_bundle", "verify_bundle", "Endpoint", "HostingTopology", "HostRecord", "MaliciousInfra",
    "generate_topology",
]
