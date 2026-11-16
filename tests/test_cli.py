from __future__ import annotations

from redthread.cli import main
from redthread.config import load_config


def test_init_and_validate(tmp_path, capsys):
    target = tmp_path / "redthread.toml"
    assert main(["init", str(target)]) == 0
    assert target.exists()
    config = load_config(target)
    assert config.run.name == "labshop"

    assert main(["validate", "-c", str(target)]) == 0
    output = capsys.readouterr().out
    assert "targets: http://127.0.0.1:8000" in output
    assert "identities: alice, bob" in output
    assert "sql-injection" in output


def test_unknown_check_is_rejected(tmp_path, capsys):
    target = tmp_path / "redthread.toml"
    assert main(["init", str(target)]) == 0
    text = target.read_text(encoding="utf-8").replace(
        "enabled = []", 'enabled = ["does-not-exist"]'
    )
    target.write_text(text, encoding="utf-8")
    assert main(["validate", "-c", str(target)]) == 2
    assert "unknown check" in capsys.readouterr().err


def test_checks_command(capsys):
    assert main(["checks"]) == 0
    output = capsys.readouterr().out
    for check_id in (
        "headers",
        "cors",
        "open-redirect",
        "reflected-xss",
        "sql-injection",
        "authz-object",
        "graphql-introspection",
    ):
        assert check_id in output


def test_missing_config_is_a_clean_error(tmp_path, capsys):
    assert main(["validate", "-c", str(tmp_path / "missing.toml")]) == 2
    assert "config error" in capsys.readouterr().err
