from __future__ import annotations

from redthread.checks.authz import ObjectAuthzCheck
from redthread.checks.base import Check, CheckContext, ValidationResult
from redthread.checks.cors import CorsCheck
from redthread.checks.graphql import GraphqlIntrospectionCheck
from redthread.checks.headers import HeaderCheck
from redthread.checks.open_redirect import OpenRedirectCheck
from redthread.checks.sqli import SqlInjectionCheck
from redthread.checks.xss import ReflectedXssCheck
from redthread.config import Config

CHECK_CLASSES: tuple[type[Check], ...] = (
    HeaderCheck,
    CorsCheck,
    OpenRedirectCheck,
    GraphqlIntrospectionCheck,
    ReflectedXssCheck,
    SqlInjectionCheck,
    ObjectAuthzCheck,
)


def all_checks() -> dict[str, Check]:
    return {cls.id: cls() for cls in CHECK_CLASSES}


def enabled_checks(config: Config) -> dict[str, Check]:
    checks = all_checks()
    if config.checks.enabled:
        missing = sorted(set(config.checks.enabled) - set(checks))
        if missing:
            raise ValueError(f"unknown check(s) in checks.enabled: {', '.join(missing)}")
        checks = {key: value for key, value in checks.items() if key in config.checks.enabled}
    for name in config.checks.disabled:
        checks.pop(name, None)
    return checks


__all__ = [
    "Check",
    "CheckContext",
    "ValidationResult",
    "all_checks",
    "enabled_checks",
]
