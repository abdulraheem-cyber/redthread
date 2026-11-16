from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from redthread.config import LlmSettings
from redthread.errors import LlmError

log = logging.getLogger(__name__)


def parse_json_object(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


class LlmClient:
    def __init__(self, settings: LlmSettings):
        self.settings = settings
        self.calls = 0
        self.enabled = bool(settings.enabled and settings.api_key and settings.max_calls)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.timeout_seconds, connect=10.0)
        )

    async def complete_json(self, system: str, user: str) -> dict[str, Any] | None:
        if not self.enabled or self.calls >= self.settings.max_calls:
            return None
        self.calls += 1
        payload = {
            "model": self.settings.model,
            "temperature": self.settings.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.settings.api_key}",
            "Content-Type": "application/json",
        }
        url = self.settings.base_url.rstrip("/") + "/chat/completions"
        for attempt in range(2):
            try:
                response = await self._client.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                if attempt == 0:
                    await asyncio.sleep(1.0)
                    continue
                raise LlmError(f"LLM request failed: {exc}") from exc
            if response.status_code in (429, 500, 502, 503, 504) and attempt == 0:
                await asyncio.sleep(1.0)
                continue
            if response.status_code >= 400:
                raise LlmError(f"LLM returned {response.status_code}: {response.text[:200]}")
            try:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise LlmError("LLM response did not contain a chat message") from exc
            parsed = parse_json_object(str(content))
            if parsed is None:
                log.warning("LLM returned text that was not a JSON object")
            return parsed
        return None

    async def close(self) -> None:
        await self._client.aclose()


class NullLlm:
    enabled = False
    calls = 0

    async def complete_json(self, system: str, user: str) -> None:
        return None

    async def close(self) -> None:
        return None


def build_llm(settings: LlmSettings) -> LlmClient | NullLlm:
    if settings.enabled and not settings.api_key:
        log.warning("llm.enabled is true but no API key is set; using the offline planner")
        return NullLlm()
    if settings.enabled:
        return LlmClient(settings)
    return NullLlm()
