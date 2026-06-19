import json
from rbacdiff.cli import main


def _snap(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return str(p)


def test_cli_exit_1_on_risky_grant(tmp_path, capsys):
    before = _snap(tmp_path, "before.json", {"alice": ["reader"]})
    after = _snap(tmp_path, "after.json", {"alice": ["reader", "admin"]})
    code = main([before, after, "--sensitive", "admin,root"])
    out = capsys.readouterr().out
    assert code == 1
    assert "Risky grants" in out and "alice" in out


def test_cli_clean_exit_0(tmp_path, capsys):
    before = _snap(tmp_path, "before.json", {"alice": ["reader"]})
    after = _snap(tmp_path, "after.json", {"alice": ["reader", "editor"]})
    code = main([before, after, "--sensitive", "admin"])
    assert code == 0
    assert "No risky grants" in capsys.readouterr().out


def test_cli_json_with_sod(tmp_path, capsys):
    before = _snap(tmp_path, "before.json", {"alice": ["create"]})
    after = _snap(tmp_path, "after.json", {"alice": ["create", "approve"]})
    sod = _snap(tmp_path, "sod.json", [{"name": "AP", "role_a": "create", "role_b": "approve"}])
    code = main([before, after, "--sod", sod, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert any(v["kind"] == "sod" for v in data["violations"])
    assert data["changes"][0]["granted"] == ["approve"]


def test_cli_bad_file(tmp_path, capsys):
    after = _snap(tmp_path, "after.json", {"a": ["b"]})
    assert main(["/nope/missing.json", after]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_catalog_drift_flags_permission_grant(tmp_path, capsys):
    # same role assignment, but the role's definition gains a sensitive permission
    before = _snap(tmp_path, "before.json", {"alice": ["dev"]})
    after = _snap(tmp_path, "after.json", {"alice": ["dev"]})
    cat_b = _snap(tmp_path, "catb.json", {"dev": ["code:write"]})
    cat_a = _snap(tmp_path, "cata.json", {"dev": ["code:write", "prod:deploy"]})
    code = main([before, after, "--catalog-before", cat_b, "--catalog-after", cat_a,
                 "--sensitive-perms", "prod:*", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert data["permission_changes"][0]["gained"] == ["prod:deploy"]
    assert data["risky_permission_grants"][0]["user"] == "alice"


def test_cli_who_can(tmp_path, capsys):
    before = _snap(tmp_path, "before.json", {"alice": ["admin"], "bob": ["dev"]})
    after = _snap(tmp_path, "after.json", {"alice": ["admin"], "bob": ["dev"]})
    cat = _snap(tmp_path, "cat.json", {"admin": ["prod:*"], "dev": ["code:write"]})
    code = main([before, after, "--catalog-after", cat, "--who-can", "prod:deploy", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data == {"permission": "prod:deploy", "users": ["alice"]}   # admin via prod:*


def test_cli_who_can_needs_catalog(tmp_path, capsys):
    before = _snap(tmp_path, "before.json", {"a": ["x"]})
    after = _snap(tmp_path, "after.json", {"a": ["x"]})
    assert main([before, after, "--who-can", "prod:deploy"]) == 2
    assert "needs a catalog" in capsys.readouterr().err


def test_cli_reports_broad_permissions(tmp_path, capsys):
    before = _snap(tmp_path, "before.json", {"alice": ["admin"]})
    after = _snap(tmp_path, "after.json", {"alice": ["admin"]})
    cat = _snap(tmp_path, "cat.json", {"admin": ["*:*"], "dev": ["code:write"]})
    main([before, after, "--catalog-after", cat, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["broad_permissions"] == {"admin": ["*:*"]}
