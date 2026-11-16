from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from redthread.errors import ConfigError

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    return value


def _table(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a table")
    return value


def _string(section: dict[str, Any], key: str, default: str = "") -> str:
    value = section.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be a string")
    return value


def _bool(section: dict[str, Any], key: str, default: bool = False) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be true or false")
    return value


def _int(section: dict[str, Any], key: str, default: int, minimum: int = 0) -> int:
    value = section.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{key} must be an integer")
    if value < minimum:
        raise ConfigError(f"{key} must be at least {minimum}")
    return value


def _float(section: dict[str, Any], key: str, default: float, minimum: float = 0.0) -> float:
    value = section.get(key, default)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfigError(f"{key} must be a number")
    if value < minimum:
        raise ConfigError(f"{key} must be at least {minimum}")
    return float(value)


def _string_list(section: dict[str, Any], key: str, default: list[str] | None = None) -> list[str]:
    value = section.get(key, default or [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{key} must be a list of strings")
    return list(value)


@dataclass(frozen=True)
class RunSettings:
    name: str = ""
    output_dir: str = "runs"
    authorized: bool = False
    allow_post: bool = False
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    max_requests: int = 800
    max_runtime_seconds: float = 900.0
    workers: int = 4
    rate_limit: float = 4.0
    stagnant_limit: int = 30
    max_baseline_actions: int = 60
    max_explore_actions: int = 80
    user_agent: str = "redthread/0.1 (+authorized exposure validation)"
    stop_file: str = ".redthread.stop"
    verify_tls: bool = True


@dataclass(frozen=True)
class ScopeSettings:
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    max_depth: int = 3
    max_pages: int = 80
    same_origin: bool = True
    crawl_identities: bool = True


@dataclass(frozen=True)
class IdentitySettings:
    name: str
    kind: str = "form"
    login_url: str = ""
    username: str = ""
    password: str = ""
    token: str = ""
    username_field: str = ""
    password_field: str = ""
    success_marker: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    extra_fields: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class LlmSettings:
    enabled: bool = False
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    api_key: str = ""
    temperature: float = 0.2
    max_calls: int = 40
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class GraphSettings:
    path: str = ""
    neo4j_uri: str = ""
    neo4j_user: str = ""
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"


@dataclass(frozen=True)
class ChecksSettings:
    enabled: tuple[str, ...] = ()
    disabled: tuple[str, ...] = ()
    max_payloads: int = 4


@dataclass(frozen=True)
class IntegrationSettings:
    nmap_enabled: bool = False
    nmap_binary: str = "nmap"
    nmap_args: str = "-sV -Pn --top-ports 100"


@dataclass(frozen=True)
class Config:
    run: RunSettings
    scope: ScopeSettings
    identities: tuple[IdentitySettings, ...]
    llm: LlmSettings
    graph: GraphSettings
    checks: ChecksSettings
    integrations: IntegrationSettings
    source: str = ""
    base_dir: str = "."

    def identity(self, name: str) -> IdentitySettings | None:
        for item in self.identities:
            if item.name == name:
                return item
        return None

    def with_llm(self, enabled: bool) -> Config:
        return replace(self, llm=replace(self.llm, enabled=enabled))

    @property
    def root(self) -> Path:
        return Path(self.base_dir)

    def output_root(self) -> Path:
        path = Path(self.run.output_dir)
        if not path.is_absolute():
            path = self.root / path
        return path.resolve()

    def run_dir(self, stamp: str) -> Path:
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", self.run.name).strip("-")
        folder = f"{stamp}-{slug}" if slug else stamp
        return self.output_root() / folder

    def stop_file(self) -> Path:
        path = Path(self.run.stop_file)
        if not path.is_absolute():
            path = self.root / path
        return path.resolve()

    def seeds(self) -> list[str]:
        targets: list[str] = []
        for item in self.scope.include:
            if "://" not in item:
                continue
            parts = urlsplit(item)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                continue
            targets.append(item.rstrip("/") or item)
        return list(dict.fromkeys(targets))

    def non_local_seeds(self) -> list[str]:
        result = []
        for seed in self.seeds():
            host = (urlsplit(seed).hostname or "").lower()
            if host in ("localhost", "::1") or host.endswith(".localhost"):
                continue
            if host.startswith("127."):
                continue
            result.append(seed)
        return result

    def redacted(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "run": {
                "name": self.run.name,
                "authorized": self.run.authorized,
                "allow_post": self.run.allow_post,
                "allowed_methods": list(self.run.allowed_methods),
                "max_requests": self.run.max_requests,
                "max_runtime_seconds": self.run.max_runtime_seconds,
                "workers": self.run.workers,
                "rate_limit": self.run.rate_limit,
                "stagnant_limit": self.run.stagnant_limit,
            },
            "scope": {
                "include": list(self.scope.include),
                "exclude": list(self.scope.exclude),
                "max_depth": self.scope.max_depth,
                "max_pages": self.scope.max_pages,
            },
            "identities": [{"name": item.name, "kind": item.kind} for item in self.identities],
            "llm": {
                "enabled": self.llm.enabled,
                "base_url": self.llm.base_url,
                "model": self.llm.model,
                "max_calls": self.llm.max_calls,
            },
            "checks": {
                "enabled": list(self.checks.enabled),
                "disabled": list(self.checks.disabled),
            },
            "integrations": {
                "nmap_enabled": self.integrations.nmap_enabled,
            },
        }


def _parse_identity(raw: dict[str, Any], index: int) -> IdentitySettings:
    if not isinstance(raw, dict):
        raise ConfigError(f"identities[{index}] must be a table")
    name = _string(raw, "name")
    if not name:
        raise ConfigError(f"identities[{index}] is missing a name")
    kind = _string(raw, "kind", "form").lower()
    allowed = {"form", "basic", "bearer", "headers", "browser"}
    if kind not in allowed:
        raise ConfigError(f"identity {name}: kind must be one of {', '.join(sorted(allowed))}")

    headers_raw = raw.get("headers", {})
    if not isinstance(headers_raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in headers_raw.items()
    ):
        raise ConfigError(f"identity {name}: headers must be a table of strings")
    extra_raw = raw.get("extra_fields", {})
    if not isinstance(extra_raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in extra_raw.items()
    ):
        raise ConfigError(f"identity {name}: extra_fields must be a table of strings")

    identity = IdentitySettings(
        name=name,
        kind=kind,
        login_url=_string(raw, "login_url"),
        username=_string(raw, "username"),
        password=_string(raw, "password"),
        token=_string(raw, "token"),
        username_field=_string(raw, "username_field"),
        password_field=_string(raw, "password_field"),
        success_marker=_string(raw, "success_marker"),
        headers=dict(headers_raw),
        extra_fields=dict(extra_raw),
    )
    if kind in ("form", "browser"):
        if not identity.login_url:
            raise ConfigError(f"identity {name}: login_url is required for {kind} auth")
        if not identity.username or not identity.password:
            raise ConfigError(f"identity {name}: username and password are required")
    if kind == "basic" and (not identity.username or not identity.password):
        raise ConfigError(f"identity {name}: username and password are required")
    if kind == "bearer" and not identity.token:
        raise ConfigError(f"identity {name}: token is required for bearer auth")
    if kind == "headers" and not identity.headers:
        raise ConfigError(f"identity {name}: headers cannot be empty")
    return identity


def load_config(path: str | Path) -> Config:
    config_path = Path(path).expanduser().resolve()
    if not config_path.exists():
        raise ConfigError(f"config not found: {config_path}")
    try:
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"could not parse {config_path.name}: {exc}") from exc

    raw = _expand_env(raw)
    known = {"run", "scope", "llm", "graph", "checks", "integrations", "identities"}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"unknown config section(s): {', '.join(unknown)}")

    run_raw = _table(raw, "run")
    scope_raw = _table(raw, "scope")
    llm_raw = _table(raw, "llm")
    graph_raw = _table(raw, "graph")
    checks_raw = _table(raw, "checks")
    integrations_raw = _table(raw, "integrations")

    allow_post = _bool(run_raw, "allow_post", False)
    methods = [item.upper() for item in _string_list(run_raw, "allowed_methods")]
    if not methods:
        methods = ["GET", "HEAD", "OPTIONS"]
    if allow_post and "POST" not in methods:
        methods.append("POST")
    if "POST" in methods and not allow_post:
        raise ConfigError("POST is listed in allowed_methods but allow_post is false")
    rejected = sorted(set(methods) - {"GET", "HEAD", "OPTIONS", "POST"})
    if rejected:
        raise ConfigError(
            "only GET, HEAD, OPTIONS and POST are supported; remove " + ", ".join(rejected)
        )

    run = RunSettings(
        name=_string(run_raw, "name"),
        output_dir=_string(run_raw, "output_dir", "runs"),
        authorized=_bool(run_raw, "authorized", False),
        allow_post=allow_post,
        allowed_methods=tuple(dict.fromkeys(methods)),
        max_requests=_int(run_raw, "max_requests", 800, 1),
        max_runtime_seconds=_float(run_raw, "max_runtime_seconds", 900.0, 1.0),
        workers=_int(run_raw, "workers", 4, 1),
        rate_limit=_float(run_raw, "rate_limit", 4.0, 0.0),
        stagnant_limit=_int(run_raw, "stagnant_limit", 30, 1),
        max_baseline_actions=_int(run_raw, "max_baseline_actions", 60, 0),
        max_explore_actions=_int(run_raw, "max_explore_actions", 80, 0),
        user_agent=_string(
            run_raw, "user_agent", "redthread/0.1 (+authorized exposure validation)"
        ),
        stop_file=_string(run_raw, "stop_file", ".redthread.stop"),
        verify_tls=_bool(run_raw, "verify_tls", True),
    )

    include = _string_list(scope_raw, "include")
    if not include:
        raise ConfigError("scope.include must list at least one target URL")
    scope = ScopeSettings(
        include=tuple(include),
        exclude=tuple(_string_list(scope_raw, "exclude")),
        max_depth=_int(scope_raw, "max_depth", 3, 1),
        max_pages=_int(scope_raw, "max_pages", 80, 1),
        same_origin=_bool(scope_raw, "same_origin", True),
        crawl_identities=_bool(scope_raw, "crawl_identities", True),
    )

    identities_raw = raw.get("identities", [])
    if not isinstance(identities_raw, list):
        raise ConfigError("identities must be an array of tables ([[identities]])")
    identities = tuple(_parse_identity(item, index) for index, item in enumerate(identities_raw))
    names = [item.name for item in identities]
    if len(names) != len(set(names)):
        raise ConfigError("identity names must be unique")

    llm = LlmSettings(
        enabled=_bool(llm_raw, "enabled", False),
        base_url=_string(llm_raw, "base_url", "https://api.openai.com/v1").rstrip("/"),
        model=_string(llm_raw, "model", "gpt-4o-mini"),
        api_key=_string(llm_raw, "api_key") or os.environ.get("REDTHREAD_LLM_API_KEY", ""),
        temperature=_float(llm_raw, "temperature", 0.2, 0.0),
        max_calls=_int(llm_raw, "max_calls", 40, 0),
        timeout_seconds=_float(llm_raw, "timeout_seconds", 30.0, 1.0),
    )

    graph = GraphSettings(
        path=_string(graph_raw, "path"),
        neo4j_uri=_string(graph_raw, "neo4j_uri"),
        neo4j_user=_string(graph_raw, "neo4j_user"),
        neo4j_password=_string(graph_raw, "neo4j_password"),
        neo4j_database=_string(graph_raw, "neo4j_database", "neo4j"),
    )

    checks = ChecksSettings(
        enabled=tuple(_string_list(checks_raw, "enabled")),
        disabled=tuple(_string_list(checks_raw, "disabled")),
        max_payloads=_int(checks_raw, "max_payloads", 4, 1),
    )

    integrations = IntegrationSettings(
        nmap_enabled=_bool(integrations_raw, "nmap_enabled", False),
        nmap_binary=_string(integrations_raw, "nmap_binary", "nmap"),
        nmap_args=_string(integrations_raw, "nmap_args", "-sV -Pn --top-ports 100"),
    )

    if not Config(
        run=run,
        scope=scope,
        identities=identities,
        llm=llm,
        graph=graph,
        checks=checks,
        integrations=integrations,
        source=str(config_path),
        base_dir=str(config_path.parent),
    ).seeds():
        raise ConfigError("scope.include needs at least one absolute http:// or https:// URL")

    return Config(
        run=run,
        scope=scope,
        identities=identities,
        llm=llm,
        graph=graph,
        checks=checks,
        integrations=integrations,
        source=str(config_path),
        base_dir=str(config_path.parent),
    )


EXAMPLE_CONFIG = """\
# redthread config. Paths are relative to this file.
# Run `python -m labs.labshop` first, then `redthread run -c examples/redthread.toml`.

[run]
name = "labshop"
output_dir = "runs"
authorized = false          # localhost only; set true only for systems you own
allow_post = true           # needed for form login and GraphQL
rate_limit = 8.0
max_requests = 600
max_runtime_seconds = 300
workers = 4
max_baseline_actions = 40
max_explore_actions = 60
stagnant_limit = 20

[scope]
include = ["http://127.0.0.1:8000"]
exclude = ["/logout", "/admin/delete*"]
max_depth = 3
max_pages = 60

[llm]
# Optional. Without a key the planner still runs, using the check order and
# past outcomes instead of model suggestions.
enabled = false
base_url = "https://api.openai.com/v1"
model = "gpt-4o-mini"
api_key = "${OPENAI_API_KEY}"
max_calls = 20

[checks]
enabled = []                # empty means all registered checks
disabled = []

[graph]
path = ""                   # defaults to graph.sqlite in the run directory

[integrations]
nmap_enabled = false

[[identities]]
name = "alice"
kind = "form"
login_url = "http://127.0.0.1:8000/login"
username = "alice"
password = "alice-pw"       # demo account; use ${ENV_VAR} in real configs
success_marker = "Signed in as alice"

[[identities]]
name = "bob"
kind = "form"
login_url = "http://127.0.0.1:8000/login"
username = "bob"
password = "bob-pw"
success_marker = "Signed in as bob"
"""


def write_example_config(path: str | Path, force: bool = False) -> Path:
    target = Path(path)
    if target.exists() and not force:
        raise ConfigError(f"{target} already exists (use --force to overwrite)")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    return target
