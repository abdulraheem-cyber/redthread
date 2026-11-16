from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".mjs",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".mp4",
    ".webp",
)

DANGEROUS_PATH = re.compile(
    r"/(logout|logoff|signout|sign-out|delete|remove|destroy|reset|revoke|unsubscribe)(/|$)",
    re.I,
)

_JS_PATH = re.compile(r"""["']((?:/|https?://)[^"'\\\s]{2,160})["']""")


def is_static_path(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(extension) for extension in STATIC_EXTENSIONS)


def is_dangerous(url: str) -> bool:
    return bool(DANGEROUS_PATH.search(urlsplit(url).path))


def normalise_url(base: str, href: str) -> str | None:
    href = href.strip()
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
        return None
    try:
        url = urljoin(base, href)
    except ValueError:
        return None
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    if is_static_path(parts.path):
        return None
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    normal = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))
    return normal if len(normal) <= 2000 else None


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: set[str] = set()
        self._in_script = False
        self._script_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag in ("a", "area") and values.get("href"):
            self.links.add(values["href"])
        elif tag in ("iframe", "frame") and values.get("src"):
            self.links.add(values["src"])
        elif tag == "script" and values.get("src"):
            self.links.add(values["src"])
        elif tag == "script":
            self._in_script = True
            self._script_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            joined = "".join(self._script_parts)
            for match in _JS_PATH.finditer(joined):
                self.links.add(match.group(1))


def links_from_html(html: str) -> set[str]:
    parser = LinkParser()
    try:
        parser.feed(html)
    except Exception:
        return set()
    return parser.links
