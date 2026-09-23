import base64

from servermanager import settings, wireguard
from servermanager.models import CONN_WIREGUARD, System


def test_keys():
    priv, pub = wireguard.generate_keypair()
    assert wireguard.valid_key(priv) and wireguard.valid_key(pub)
    assert wireguard.public_from_private(priv) == pub
    assert not wireguard.valid_key("abc")
    assert len(base64.b64decode(pub)) == 32


def test_subnets():
    assert wireguard.parse_subnets("192.168.1.5/24, 10.0.0.0/8") == ["192.168.1.0/24", "10.0.0.0/8"]
    import pytest
    with pytest.raises(ValueError):
        wireguard.parse_subnets("nonsense")


def test_allocation_and_config(db):
    settings.set(db, "wg.network", "10.77.0.0/28")
    settings.set(db, "wg.router_ip", "10.77.0.1")
    settings.set(db, "wg.sm_ip", "10.77.0.2")
    settings.set(db, "wg.pool_start", 3)
    db.add(System(name="wg-a", connection=CONN_WIREGUARD, wg_ip="10.77.0.3", routed_subnets="192.168.9.0/24"))
    db.flush()
    assert wireguard.allocate_ip(db) == "10.77.0.4"
    assert wireguard.allocate_ip(db, extra_used={"10.77.0.4"}) == "10.77.0.5"
    wireguard.ensure_sm_keypair(db)
    settings.set(db, "wg.router_public_key", wireguard.generate_keypair()[1])
    settings.set(db, "wg.endpoint", "vpn.example.com:13231")
    conf = wireguard.render_sm_config(db)
    assert "Address = 10.77.0.2/32" in conf
    allowed = conf.split("AllowedIPs = ")[1].splitlines()[0].split(", ")
    assert allowed[0] == "10.77.0.0/28" and "192.168.9.0/24" in allowed
    assert "PostUp" not in conf
    script = wireguard.routeros_script(db)
    assert "/interface wireguard add name=wg-mgmt" in script
    assert "allowed-address=10.77.0.2/32" in script
