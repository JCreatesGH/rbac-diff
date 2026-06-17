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
