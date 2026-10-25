import ipaddress

from aegis.lab.topology import HostingTopology, dga_domains, generate_topology

RESERVED = [ipaddress.ip_network(n) for n in ("198.18.0.0/15", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_deterministic():
    assert generate_topology(7).to_dict(True) == generate_topology(7).to_dict(True)
    assert generate_topology(7).to_dict() != generate_topology(8).to_dict()


def test_only_reserved_addresses_and_names():
    topo = generate_topology(7)
    for ip, host in topo.hosts.items():
        assert any(ipaddress.ip_address(ip) in n for n in RESERVED), ip
        for name in host.hostnames:
            assert name.endswith((".example", ".test")), name
    for name in dga_domains(1, 2, 50):
        assert name.endswith(".test")


def test_shared_cdn_cotenants_and_malicious_cohosting():
    topo = generate_topology(7)
    bb = topo.malicious["badbox2_emu"]
    (shared_ip,) = topo.resolve(bb.cohosted_domains[0])
    assert topo.is_shared(shared_ip) is True
    cot = topo.cotenants(shared_ip, exclude=bb.cohosted_domains)
    assert len(cot) >= 20 and not (set(cot) & topo.all_malicious_domains())
    for ip in bb.c2_ips:
        assert topo.is_shared(ip) is False and topo.host(ip).kind == "dedicated"
    assert topo.is_shared("8.8.8.8") is None and topo.cotenants("8.8.8.8") == []
    assert topo.covers("198.18.1.1") and not topo.covers("8.8.8.8") and not topo.covers("garbage")
    assert topo.asn_of(shared_ip) in (64600, 64601) and topo.asn_of("8.8.8.8") is None


def test_services_resolve_consistently():
    topo = generate_topology(7)
    for name, eps in topo.services.items():
        assert eps, name
        for ep in eps:
            assert ep.ip in topo.resolve(ep.hostname)
    assert "edge00.streamcdn.example" in topo.domains()


def test_round_trip_and_ground_truth_separation(tmp_path):
    topo = generate_topology(3)
    public = topo.to_dict()
    assert "lab_ground_truth" not in public
    p = topo.save(tmp_path / "t.json")
    loaded = HostingTopology.load(p)
    assert loaded.to_dict() == public and loaded.malicious == {}
    full = HostingTopology.from_dict(topo.to_dict(include_ground_truth=True))
    assert full.malicious.keys() == topo.malicious.keys()


def test_dga_is_deterministic_per_day():
    assert dga_domains(5, 100, 10) == dga_domains(5, 100, 10)
    assert dga_domains(5, 100, 10) != dga_domains(5, 101, 10)
    assert all(12 <= len(d.split(".")[0]) <= 18 for d in dga_domains(5, 100, 100))
