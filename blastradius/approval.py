"""Approval signatures and write-tool authorisation tokens.

Approvals are signed with HMAC-SHA256 over the plan hash, the approver and the
decision. When a wave is approved, the authority issues one token per
(run, wave, asset, action). Write tools refuse to run without a valid token, so
an agent cannot touch an asset a human did not approve, even if it calls the
MCP server directly.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from .ledger import canonical


class ApprovalAuthority:
    def __init__(self, signing_key: str):
        self._key = signing_key.encode()
        self._grants: dict[str, set[tuple[str, str]]] = {}  # run_id -> {(asset, action)}
        self._revoked: set[str] = set()

    def sign(self, obj) -> str:
        return hmac.new(self._key, canonical(obj).encode(), hashlib.sha256).hexdigest()

    def verify_signature(self, obj, signature: str) -> bool:
        return hmac.compare_digest(self.sign(obj), signature)

    def sign_approval(self, run_id: str, plan_hash: str, scope: str, approver: str, decision: str, comment: str = "") -> dict:
        record = {
            "run_id": run_id,
            "plan_hash": plan_hash,
            "scope": scope,
            "approver": approver,
            "decision": decision,
            "comment": comment,
            "ts": round(time.time(), 3),
        }
        record["signature"] = self.sign({k: v for k, v in record.items()})
        return record

    # ------------------------------------------------------------ write tokens
    def grant(self, run_id: str, assets: list[str], actions: list[str]) -> dict[str, str]:
        tokens = {}
        g = self._grants.setdefault(run_id, set())
        for a in assets:
            for act in actions:
                g.add((a, act))
                tokens[f"{a}|{act}"] = self.token(run_id, a, act)
        return tokens

    def token(self, run_id: str, asset: str, action: str) -> str:
        return hmac.new(self._key, f"{run_id}|{asset}|{action}".encode(), hashlib.sha256).hexdigest()[:32]

    def check(self, token: str, run_id: str, asset: str, action: str) -> tuple[bool, str]:
        if run_id in self._revoked:
            return False, f"run {run_id} has been halted; write access revoked"
        if (asset, action) not in self._grants.get(run_id, set()):
            return False, f"{action} on {asset} is not part of an approved wave for run {run_id}"
        if not token or not hmac.compare_digest(token, self.token(run_id, asset, action)):
            return False, "invalid approval token"
        return True, "ok"

    def revoke_run(self, run_id: str) -> None:
        self._revoked.add(run_id)
        self._grants.pop(run_id, None)

    def reinstate_run(self, run_id: str) -> None:
        self._revoked.discard(run_id)
