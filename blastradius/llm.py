"""LLM clients.

* ``OpenAICompatClient`` talks to any OpenAI-compatible chat-completions endpoint
  (NVIDIA NIM on HPE Private Cloud AI, an HPE GenAI Hub / ChatHPE gateway) or to
  Azure OpenAI. Only HPE-approved endpoints should be configured.
* ``OfflineLLM`` is a deterministic stand-in so the demo and tests run with no
  network. It receives the same structured context the real prompt is built
  from, and returns output of the same schema.

Every prompt is passed through policy redaction before it leaves the process,
and every call is summarised (model, role, prompt hash, latency) for the ledger.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from .config import Settings
from .policy import Policy


def load_prompt(name: str) -> str:
    return resources.files("blastradius.prompts").joinpath(f"{name}.md").read_text()


class LLMError(RuntimeError):
    pass


@dataclass
class CallRecord:
    role: str
    model: str
    prompt_sha256: str
    latency_ms: int
    ok: bool
    note: str = ""


@dataclass
class LLMClient:
    model: str
    mode: str
    history: list[CallRecord] = field(default_factory=list)

    def complete_json(self, role: str, system: str, user: str, schema: type[BaseModel], context: dict,
                      temperature: float = 0.2) -> BaseModel:
        raise NotImplementedError

    def last(self) -> dict:
        return self.history[-1].__dict__ if self.history else {}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _extract_json(text: str) -> Any:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1)
    start = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=-1)
    if start > 0:
        text = text[start:]
    return json.loads(text)


class OpenAICompatClient(LLMClient):
    def __init__(self, base_url: str, api_key: str, model: str, api_style: str, api_version: str,
                 timeout_s: float, redact: Callable[[str], str]):
        super().__init__(model=model, mode=api_style)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_version = api_version
        self.timeout_s = timeout_s
        self.redact = redact

    def _post(self, messages: list[dict], temperature: float) -> str:
        body: dict[str, Any] = {"messages": messages, "temperature": temperature,
                                "response_format": {"type": "json_object"}}
        headers = {"Content-Type": "application/json"}
        if self.mode == "azure":
            url = f"{self.base_url}/openai/deployments/{self.model}/chat/completions?api-version={self.api_version}"
            headers["api-key"] = self.api_key
        else:
            url = f"{self.base_url}/chat/completions"
            body["model"] = self.model
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise LLMError(f"LLM endpoint returned HTTP {e.code}: {e.read()[:300]!r}") from e
        except urllib.error.URLError as e:
            raise LLMError(f"LLM endpoint unreachable: {e.reason}") from e
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"unexpected LLM response shape: {str(data)[:300]}") from e

    def complete_json(self, role, system, user, schema, context, temperature=0.2):
        messages = [{"role": "system", "content": self.redact(system)}, {"role": "user", "content": self.redact(user)}]
        t0 = time.time()
        last_err = ""
        for attempt in range(3):
            raw = self._post(messages, temperature)
            try:
                out = schema.model_validate(_extract_json(raw))
                self.history.append(CallRecord(role, self.model, _sha(system + user), int((time.time() - t0) * 1000), True,
                                               f"attempt {attempt + 1}"))
                return out
            except (json.JSONDecodeError, ValidationError) as e:
                last_err = str(e)[:500]
                messages = messages + [
                    {"role": "assistant", "content": raw},
                    {"role": "user", "content": f"That output did not match the required JSON schema: {last_err}\n"
                                                "Return only corrected JSON."},
                ]
        self.history.append(CallRecord(role, self.model, _sha(system + user), int((time.time() - t0) * 1000), False, last_err))
        raise LLMError(f"{role}: model output failed schema validation 3 times: {last_err}")


class OfflineLLM(LLMClient):
    def __init__(self, name: str = "offline-deterministic"):
        super().__init__(model=name, mode="offline")

    def complete_json(self, role, system, user, schema, context, temperature=0.2):
        from . import offline_llm

        t0 = time.time()
        out = offline_llm.respond(role, context)
        self.history.append(CallRecord(role, self.model, _sha(system + user), int((time.time() - t0) * 1000), True))
        return schema.model_validate(out)


def make_llm(settings: Settings, policy: Policy) -> tuple[LLMClient, LLMClient]:
    if settings.offline:
        return OfflineLLM("offline-planner"), OfflineLLM("offline-verifier")
    if not settings.llm_base_url:
        raise LLMError("BR_LLM_MODE is not 'offline' but BR_LLM_BASE_URL is empty")
    style = "azure" if settings.llm_mode == "azure" else "openai"
    planner = OpenAICompatClient(settings.llm_base_url, settings.llm_api_key, settings.llm_model, style,
                                 settings.llm_api_version, settings.llm_timeout_s, policy.redact)
    verifier = OpenAICompatClient(settings.verifier_base_url or settings.llm_base_url,
                                  settings.verifier_api_key or settings.llm_api_key,
                                  settings.verifier_model or settings.llm_model, style,
                                  settings.llm_api_version, settings.llm_timeout_s, policy.redact)
    return planner, verifier
