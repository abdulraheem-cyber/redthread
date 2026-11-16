from __future__ import annotations

import pytest

from redthread.config import ConfigError, load_config, write_example_config
from tests.helpers import config_text


def test_env_expansion_and_redaction(tmp_path, monkeypatch):
    monkeypatch.setenv("LAB_PASSWORD", "from-environment")
    text = config_text("http://127.0.0.1:8000").replace("alice-pw", "${LAB_PASSWORD}")
    path = tmp_path / "redthread.toml"
    path.write_text(text, encoding="utf-8")
    config = load_config(path)
    alice = config.identity("alice")
    assert alice is not None and alice.password == "from-environment"
    rendered = str(config.redacted())
    assert "from-environment" not in rendered
    assert "alice-pw" not in rendered


def test_unknown_sections_are_rejected(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text(
        config_text("http://127.0.0.1:8000") + "\n[unexpected]\nvalue = 1\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="unknown config section"):
        load_config(path)


def test_post_must_be_enabled_explicitly(tmp_path):
    text = config_text("http://127.0.0.1:8000").replace("allow_post = true", "allow_post = false")
    path = tmp_path / "bad.toml"
    path.write_text(text, encoding="utf-8")
    # The config generator does not list POST explicitly, so it loads cleanly.
    assert "POST" not in load_config(path).run.allowed_methods

    text = text.replace(
        "allow_post = false", 'allow_post = false\nallowed_methods = ["GET", "POST"]'
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="allow_post"):
        load_config(path)


def test_identity_requires_credentials(tmp_path):
    text = config_text("http://127.0.0.1:8000").replace('password = "alice-pw"', 'password = ""')
    path = tmp_path / "bad.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="username and password"):
        load_config(path)


def test_example_config_round_trips(tmp_path):
    target = write_example_config(tmp_path / "redthread.toml")
    config = load_config(target)
    assert config.run.allow_post is True
    assert [item.name for item in config.identities] == ["alice", "bob"]
    assert config.seeds() == ["http://127.0.0.1:8000"]
    assert config.output_root() == (tmp_path / "runs").resolve()
    assert config.stop_file() == (tmp_path / ".redthread.stop").resolve()
