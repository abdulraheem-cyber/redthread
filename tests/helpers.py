from __future__ import annotations

from pathlib import Path

from redthread.config import Config, load_config


def config_text(
    base_url: str,
    *,
    output_dir: str = "runs",
    max_requests: int = 400,
    max_pages: int = 40,
    allow_post: bool = True,
    authorized: bool = False,
    rate_limit: float = 0.0,
    max_explore_actions: int = 20,
) -> str:
    return f"""\
[run]
name = "labshop-test"
output_dir = "{output_dir}"
authorized = {str(authorized).lower()}
allow_post = {str(allow_post).lower()}
rate_limit = {rate_limit}
max_requests = {max_requests}
max_runtime_seconds = 90
workers = 3
max_baseline_actions = 40
max_explore_actions = {max_explore_actions}
stagnant_limit = 10

[scope]
include = ["{base_url}"]
exclude = ["/logout"]
max_depth = 3
max_pages = {max_pages}
same_origin = true

[llm]
enabled = false

[checks]
enabled = []
disabled = []

[integrations]
nmap_enabled = false

[[identities]]
name = "alice"
kind = "form"
login_url = "{base_url}/login"
username = "alice"
password = "alice-pw"
success_marker = "Signed in as alice"

[[identities]]
name = "bob"
kind = "form"
login_url = "{base_url}/login"
username = "bob"
password = "bob-pw"
success_marker = "Signed in as bob"
"""


def write_config(path: Path, base_url: str, **kwargs) -> Config:
    path.write_text(config_text(base_url, **kwargs), encoding="utf-8")
    return load_config(path)
