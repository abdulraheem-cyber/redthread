from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from redthread.config import Config
from redthread.errors import ScopeError

_DEFAULT_PORTS = {"http": 80, "https": 443}
_SENSITIVE_KEY = re.compile(
    r"(password|passwd|pass|pwd|token|secret|api[_-]?key|apikey|auth|session|sig|code|key)$",
    re.I,
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_loopback(host: str) -> bool:
    host = host.strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class Rule:
    raw: str
    scheme: str | None
    host: str
    port: int | None
    path_prefix: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None

    def matches(self, scheme: str, host: str, port: int, path: str) -> bool:
        if self.scheme is not None and self.scheme != scheme:
            return False
        if self.port is not None and self.port != port:
            return False
        if self.path_prefix != "/":
            if path != self.path_prefix and not path.startswith(self.path_prefix + "/"):
                return False
        if self.network is not None:
            if not _is_ip(host):
                return False
            try:
                return ipaddress.ip_address(host) in self.network
            except ValueError:
                return False
        if self.host.startswith("*."):
            suffix = self.host[1:]
            return host.endswith(suffix) and host != self.host[2:]
        if "*" in self.host:
            return fnmatch.fnmatch(host, self.host)
        return host == self.host


def _parse_rule(raw: str) -> Rule:
    raw = raw.strip()
    if not raw:
        raise ScopeError("empty scope entry")

    if "://" in raw:
        parts = urlsplit(raw)
        if parts.scheme not in ("http", "https"):
            raise ScopeError(f"unsupported scheme in scope entry: {raw}")
        if not parts.hostname:
            raise ScopeError(f"scope entry has no host: {raw}")
        if parts.query or parts.fragment:
            raise ScopeError(f"scope entry cannot contain a query or fragment: {raw}")
        try:
            port = parts.port
        except ValueError as exc:
            raise ScopeError(f"invalid port in scope entry: {raw}") from exc
        prefix = parts.path.rstrip("/") or "/"
        return Rule(raw, parts.scheme, parts.hostname.lower(), port, prefix)

    if "/" in raw and not raw.startswith("/"):
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            network = None
        if network is not None:
            return Rule(raw, None, str(network), None, "/", network)

    parts = urlsplit("//" + raw)
    if not parts.hostname:
        raise ScopeError(f"cannot parse scope entry: {raw}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ScopeError(f"invalid port in scope entry: {raw}") from exc
    prefix = parts.path.rstrip("/") or "/"
    host = parts.hostname.lower()
    if not _is_ip(host) and "*" not in host and "." not in host and host != "localhost":
        raise ScopeError(f"scope host looks wrong: {raw}")
    return Rule(raw, None, host, port, prefix)


def _effective_port(parts) -> int:
    if parts.port is not None:
        return parts.port
    return _DEFAULT_PORTS.get(parts.scheme, 0)


def _excluded(url: str, patterns: tuple[str, ...]) -> str | None:
    parts = urlsplit(url)
    path = parts.path or "/"
    path_query = path
    if parts.query:
        path_query += "?" + parts.query
    for pattern in patterns:
        if pattern.startswith(("http://", "https://")):
            if fnmatch.fnmatch(url, pattern) or fnmatch.fnmatch(url.split("?", 1)[0], pattern):
                return pattern
            continue
        if fnmatch.fnmatch(path, pattern):
            return pattern
        if "*" not in pattern and not pattern.endswith("/"):
            base = pattern.rstrip("/")
            if path == base or path.startswith(base + "/"):
                return pattern
    return None


class Scope:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rules = tuple(_parse_rule(item) for item in cfg.scope.include)
        self.excludes = cfg.scope.exclude
        self.methods = frozenset(item.upper() for item in cfg.run.allowed_methods)
        self._seeds = self._collect_seeds()
        self._origins = {self.origin(seed) for seed in self._seeds}

    def _collect_seeds(self) -> list[str]:
        seeds: list[str] = []
        for rule in self.rules:
            if rule.scheme is None:
                continue
            parts = urlsplit(rule.raw)
            path = parts.path or "/"
            seed = urlunsplit((rule.scheme, parts.netloc, path, "", ""))
            seeds.append(seed)
        if not seeds:
            raise ScopeError(
                "scope.include needs at least one URL with a scheme, e.g. http://127.0.0.1:8000"
            )
        return list(dict.fromkeys(seed.rstrip("/") or seed for seed in seeds))

    @property
    def seeds(self) -> tuple[str, ...]:
        return tuple(self._seeds)

    @property
    def origins(self) -> frozenset[str]:
        return frozenset(self._origins)

    @staticmethod
    def origin(url: str) -> str:
        parts = urlsplit(url)
        port = parts.port
        default = _DEFAULT_PORTS.get(parts.scheme)
        netloc = parts.hostname or ""
        if port is not None and port != default:
            netloc = f"{netloc}:{port}"
        return f"{parts.scheme}://{netloc}"

    def is_same_origin(self, url: str) -> bool:
        return self.origin(url) in self._origins

    def check(self, url: str, method: str = "GET") -> None:
        method = method.upper()
        if method not in self.methods:
            raise ScopeError(f"{method} is not an allowed method")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ScopeError(f"not an absolute http(s) URL: {url}")
        if parts.username or parts.password:
            raise ScopeError("URLs with embedded credentials are not allowed")
        excluded = _excluded(url, self.excludes)
        if excluded:
            raise ScopeError(f"{url} matches exclude pattern {excluded}")
        host = parts.hostname.lower()
        port = _effective_port(parts)
        path = parts.path or "/"
        for rule in self.rules:
            if rule.matches(parts.scheme, host, port, path):
                return
        raise ScopeError(f"{url} is outside scope")

    def require_authorization(self) -> None:
        if self.cfg.run.authorized:
            return
        outside = [
            seed for seed in self._seeds if not is_loopback((urlsplit(seed).hostname or "").lower())
        ]
        if outside:
            raise ScopeError(
                f"refusing to test a non-local target without run.authorized = true ({outside[0]})"
            )

    def check_redirect(self, current: str, location: str) -> str:
        from urllib.parse import urljoin

        target = urljoin(current, location)
        self.check(target, "GET")
        return target


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    redacted = [(key, "REDACTED" if _SENSITIVE_KEY.search(key) else value) for key, value in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(redacted), parts.fragment))


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in ("authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"):
            cleaned[key] = "REDACTED"
        else:
            cleaned[key] = value
    return cleaned
