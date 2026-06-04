from rbacdiff import load_snapshot, sod_violations, over_privileged, SodRule


SNAP = load_snapshot({
    "alice": ["ap_invoice_create", "ap_invoice_approve", "reader"],
    "bob": ["admin", "security_admin"],
    "carol": ["reader"],
})


def test_sod_violation_detected():
    rules = [SodRule("AP segregation", "ap_invoice_create", "ap_invoice_approve")]
    v = sod_violations(SNAP, rules)
    assert len(v) == 1
    assert v[0].user == "alice" and v[0].kind == "sod"


def test_no_sod_for_compliant_user():
    rules = [SodRule("x", "role_a", "role_b")]
    assert sod_violations(load_snapshot({"u": ["role_a"]}), rules) == []


def test_over_privilege_sensitive_roles():
    v = over_privileged(SNAP, sensitive_roles={"admin", "security_admin"})
    users = {x.user for x in v}
    assert users == {"bob"}
    assert "sensitive" in v[0].detail


def test_over_privilege_max_roles():
    v = over_privileged(SNAP, sensitive_roles=set(), max_roles=2)
    assert any("3 roles" in x.detail and x.user == "alice" for x in v)
