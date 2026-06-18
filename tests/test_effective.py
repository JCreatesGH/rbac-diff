from rbacdiff import (
    Snapshot, RoleCatalog, load_catalog,
    effective_permissions, permission_changes, risky_permission_grants,
)


def test_permissions_of_with_inheritance():
    cat = RoleCatalog("c", grants={"admin": {"prod:deploy"}, "dev": {"code:write"}},
                      inherits={"admin": {"dev"}})
    assert cat.permissions_of("admin") == {"prod:deploy", "code:write"}
    assert cat.permissions_of("dev") == {"code:write"}
    assert cat.permissions_of("unknown") == set()


def test_inheritance_is_cycle_safe():
    cat = RoleCatalog("c", grants={"a": {"p1"}, "b": {"p2"}},
                      inherits={"a": {"b"}, "b": {"a"}})
    assert cat.permissions_of("a") == {"p1", "p2"}   # must not loop forever


def test_load_catalog_forms():
    flat = load_catalog({"dev": ["code:write"]})
    assert flat.permissions_of("dev") == {"code:write"}
    rich = load_catalog({"name": "v2", "roles": {
        "admin": {"permissions": ["prod:deploy"], "inherits": ["dev"]},
        "dev": ["code:write"],
    }})
    assert rich.name == "v2"
    assert rich.permissions_of("admin") == {"prod:deploy", "code:write"}


def test_effective_permissions():
    snap = Snapshot("s", {"alice": {"admin"}, "bob": {"dev"}})
    cat = load_catalog({"admin": ["prod:deploy", "code:write"], "dev": ["code:write"]})
    eff = effective_permissions(snap, cat)
    assert eff["alice"] == {"prod:deploy", "code:write"}
    assert eff["bob"] == {"code:write"}


def test_permission_changes_catch_role_definition_drift():
    # identical role assignments, but the 'dev' role's definition gained a permission
    before_snap = Snapshot("b", {"alice": {"dev"}})
    after_snap = Snapshot("a", {"alice": {"dev"}})
    before_cat = load_catalog({"dev": ["code:write"]})
    after_cat = load_catalog({"dev": ["code:write", "prod:deploy"]})
    changes = permission_changes(before_snap, after_snap, before_cat, after_cat)
    assert len(changes) == 1
    assert changes[0].user == "alice" and changes[0].gained == {"prod:deploy"}


def test_risky_permission_grants_wildcard():
    before_snap = Snapshot("b", {"alice": {"dev"}})
    after_snap = Snapshot("a", {"alice": {"dev", "ops"}})
    cat = load_catalog({"dev": ["code:write"], "ops": ["prod:deploy", "db:delete"]})
    changes = permission_changes(before_snap, after_snap, cat, cat)
    risky = risky_permission_grants(changes, {"prod:*", "*:delete"})
    assert len(risky) == 1
    assert "prod:deploy" in risky[0].detail and "db:delete" in risky[0].detail
    # a non-matching pattern flags nothing
    assert risky_permission_grants(changes, {"k8s:*"}) == []
