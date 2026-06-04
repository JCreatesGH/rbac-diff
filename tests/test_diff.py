from rbacdiff import load_snapshot, diff_snapshots


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
