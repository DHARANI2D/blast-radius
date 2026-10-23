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
import http.client
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

    supports_tools = False

    def complete_json(self, role: str, system: str, user: str, schema: type[BaseModel], context: dict,
                      temperature: float = 0.2) -> BaseModel:
        raise NotImplementedError

    def chat_tools(self, role: str, messages: list[dict], tools: list[dict], temperature: float = 0.0) -> dict:
        """One function-calling turn. Returns {"content", "tool_calls": [{"id", "name", "arguments"}], "message"}."""
        raise NotImplementedError

    def last(self) -> dict:
        return self.history[-1].__dict__ if self.history else {}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


_THINK = re.compile(r"<think>.*?</think>", re.S | re.I)
_FENCE = re.compile(r"```(json)?[ \t]*\n?(.*?)```", re.S | re.I)


def _extract_json(text: str, validate: Callable[[Any], Any] = lambda v: v) -> Any:
    """The first JSON value in a model reply that decodes and passes ``validate``.

    Models wrap JSON in <think> blocks, several fences (a draft, then the answer), and prose
    or citation brackets ("Based on [EV-0042] ...") before and after it. Fenced blocks are
    tried first, the last ```json fence before the others; within each candidate every
    '{' / '[' is tried with raw_decode, which ignores whatever text follows the value.
    """
    text = _THINK.sub("", text or "").strip()
    fences = _FENCE.findall(text)
    candidates = ([b for tag, b in reversed(fences) if tag] + [b for tag, b in reversed(fences) if not tag] + [text])
    decoder = json.JSONDecoder()
    first_err: Exception | None = None
    for cand in candidates:
        for i, ch in enumerate(cand):
            if ch not in "{[":
                continue
            try:
                value, _ = decoder.raw_decode(cand, i)
            except json.JSONDecodeError:
                continue
            try:
                return validate(value)
            except ValidationError as e:
                first_err = first_err or e
    if first_err is not None:
        raise first_err
    return json.loads(text)  # raises the JSONDecodeError the repair prompt quotes


# Rate limits and gateway hiccups are retried; anything else (and a timeout, which a retry would
# only repeat) surfaces as LLMError so the caller's deterministic fallback takes over.
RETRY_STATUS = {429, 500, 502, 503, 504}


class OpenAICompatClient(LLMClient):
    retries = 2
    retry_backoff_s = 1.0

    def __init__(self, base_url: str, api_key: str, model: str, api_style: str, api_version: str,
                 timeout_s: float, redact: Callable[[str], str]):
        super().__init__(model=model, mode=api_style)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_version = api_version
        self.timeout_s = timeout_s
        self.redact = redact

    supports_tools = True

    def _post(self, messages: list[dict], temperature: float) -> str:
        msg = self._request({"messages": messages, "temperature": temperature, "response_format": {"type": "json_object"}})
        content = msg.get("content")
        # Reasoning models can return content null; an empty reply goes through the repair loop.
        return content if isinstance(content, str) else ""

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        try:
            return min(30.0, float(retry_after))
        except (TypeError, ValueError):
            return self.retry_backoff_s * 2 ** attempt

    def _request(self, body: dict[str, Any]) -> dict:
        """POST a chat-completions request and return ``choices[0].message``."""
        headers = {"Content-Type": "application/json"}
        if self.mode == "azure":
            url = f"{self.base_url}/openai/deployments/{self.model}/chat/completions?api-version={self.api_version}"
            headers["api-key"] = self.api_key
        else:
            url = f"{self.base_url}/chat/completions"
            body["model"] = self.model
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
        payload = json.dumps(body).encode()
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    raw = resp.read()
                break
            except urllib.error.HTTPError as e:
                if e.code in RETRY_STATUS and attempt < self.retries:
                    time.sleep(self._backoff(attempt, e.headers.get("Retry-After") if e.headers else None))
                    continue
                raise LLMError(f"LLM endpoint returned HTTP {e.code}: {e.read()[:300]!r}") from e
            except urllib.error.URLError as e:
                raise LLMError(f"LLM endpoint unreachable: {e.reason}") from e
            except (ConnectionError, http.client.HTTPException) as e:  # dropped connection: retry
                if attempt < self.retries:
                    time.sleep(self._backoff(attempt, None))
                    continue
                raise LLMError(f"LLM endpoint failed: {type(e).__name__}: {e}") from e
            except OSError as e:  # TimeoutError while waiting for the reply, and other socket errors
                raise LLMError(f"LLM endpoint failed: {type(e).__name__}: {e}") from e
        try:
            data = json.loads(raw.decode())
        except ValueError as e:  # an HTML login page from a gateway, a truncated body
            raise LLMError(f"LLM endpoint returned a non-JSON body: {raw[:200]!r}") from e
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"unexpected LLM response shape: {str(data)[:300]}") from e
        if not isinstance(msg, dict):
            raise LLMError(f"unexpected LLM message: {str(msg)[:300]}")
        return msg

    def chat_tools(self, role, messages, tools, temperature=0.0):
        safe = [dict(m, content=self.redact(m["content"])) if isinstance(m.get("content"), str) else m for m in messages]
        t0 = time.time()
        body: dict[str, Any] = {"messages": safe, "temperature": temperature}
        if tools:  # OpenAI rejects an empty tools array, and tool_choice without tools (the final no-tools turn)
            body.update(tools=tools, tool_choice="auto")
        msg = self._request(body)
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except (json.JSONDecodeError, TypeError, ValueError):
                args = {}
            calls.append({"id": tc.get("id") or f"call_{len(calls)}", "name": fn.get("name", ""), "arguments": args})
        self.history.append(CallRecord(role, self.model, _sha(json.dumps(safe, default=str)), int((time.time() - t0) * 1000), True,
                                       f"{len(calls)} tool call(s)"))
        return {"content": msg.get("content"), "tool_calls": calls, "message": msg}

    def complete_json(self, role, system, user, schema, context, temperature=0.2):
        messages = [{"role": "system", "content": self.redact(system)}, {"role": "user", "content": self.redact(user)}]
        sent = _sha(messages[0]["content"] + messages[1]["content"])  # the prompt that left the process, after redaction
        t0 = time.time()
        last_err = ""
        for attempt in range(3):
            raw = self._post(messages, temperature)
            try:
                out = _extract_json(raw, schema.model_validate)
                self.history.append(CallRecord(role, self.model, sent, int((time.time() - t0) * 1000), True, f"attempt {attempt + 1}"))
                return out
            except (json.JSONDecodeError, ValidationError) as e:
                last_err = str(e)[:500]
                messages = messages + [
                    {"role": "assistant", "content": raw},
                    {"role": "user", "content": f"That output did not match the required JSON schema: {last_err}\n"
                                                "Return only corrected JSON."},
                ]
        self.history.append(CallRecord(role, self.model, sent, int((time.time() - t0) * 1000), False, last_err))
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
