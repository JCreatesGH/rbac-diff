from rbacdiff import load_snapshot, diff_snapshots, risky_grants


def test_grant_and_revoke():
    a = load_snapshot({"alice": ["reader"], "bob": ["admin"]}, "before")
    b = load_snapshot({"alice": ["reader", "approver"], "carol": ["reader"]}, "after")
    changes = {c.user: c for c in diff_snapshots(a, b)}
    assert changes["alice"].granted == {"approver"}
    assert changes["bob"].revoked == {"admin"}        # bob removed entirely
    assert changes["carol"].granted == {"reader"}     # new user


def test_no_change():
    a = load_snapshot({"x": ["r"]})
    assert diff_snapshots(a, a) == []


def test_risky_grants_flags_newly_granted_sensitive_roles():
    a = load_snapshot({"alice": ["reader"], "bob": ["admin"]})
    b = load_snapshot({"alice": ["reader", "admin"], "bob": ["admin"]})
    changes = diff_snapshots(a, b)
    risky = risky_grants(changes, sensitive_roles={"admin", "root"})
    # alice newly got admin; bob already had it (not a *new* grant) -> only alice
    assert [v.user for v in risky] == ["alice"]
    assert risky[0].kind == "risky-grant" and "admin" in risky[0].detail
