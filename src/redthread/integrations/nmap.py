from __future__ import annotations

import asyncio
import shlex
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Service:
    host: str
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""


@dataclass
class NmapResult:
    hosts: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    error: str = ""


def parse_nmap_xml(data: str) -> NmapResult:
    result = NmapResult()
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        result.error = f"could not parse nmap XML: {exc}"
        return result
    for host in root.findall("host"):
        address = host.find("address")
        host_value = address.get("addr", "") if address is not None else ""
        if not host_value:
            continue
        result.hosts.append(host_value)
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            result.services.append(
                Service(
                    host=host_value,
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    state=state.get("state", "") if state is not None else "",
                    name=service.get("name", "") if service is not None else "",
                    product=service.get("product", "") if service is not None else "",
                    version=service.get("version", "") if service is not None else "",
                )
            )
    return result


class NmapRunner:
    def __init__(self, binary: str = "nmap", args: str = "-sV -Pn --top-ports 100"):
        self.binary = binary
        self.args = args

    async def scan(self, targets: list[str], timeout: float = 180.0) -> NmapResult:
        hosts = []
        for target in targets:
            parts = urlsplit(target)
            hosts.append(parts.hostname or target)
        hosts = list(dict.fromkeys(host for host in hosts if host))
        if not hosts:
            return NmapResult(error="no hosts to scan")
        try:
            process = await asyncio.create_subprocess_exec(
                self.binary,
                *shlex.split(self.args),
                "-oX",
                "-",
                *hosts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return NmapResult(error=f"nmap binary not found: {self.binary}")
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            return NmapResult(error="nmap timed out")
        if process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            return NmapResult(error=message or f"nmap exited with {process.returncode}")
        return parse_nmap_xml(stdout.decode("utf-8", errors="replace"))
