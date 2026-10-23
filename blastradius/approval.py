"""Approval signatures and write-tool authorisation tokens.

Approvals are signed with HMAC-SHA256 over the plan hash, the approver and the
decision. When a scope (the canary, then the fleet waves) is approved, the
authority grants (run, asset, action, version): firmware writes are bound to the
approved target version, or to the captured previous version for a rollback.
Write tools refuse to run without a valid token, so an agent cannot touch an
asset a human did not approve, even if it calls the MCP server directly. Every
grant of a run is revoked when the run ends.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from .ledger import canonical

# Write actions whose grant and token name the firmware version they may install.
VERSIONED_ACTIONS = ("compute.apply_firmware", "network.upgrade_switch_os")


class ApprovalAuthority:
    def __init__(self, signing_key: str):
        self._key = signing_key.encode()
        self._grants: dict[str, set[tuple[str, str, str]]] = {}  # run_id -> {(asset, action, version)}
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
    def grant(self, run_id: str, assets: list[str], actions: list[str], versions: dict[str, list[str]] | None = None) -> dict[str, str]:
        """Grant actions on assets. A versioned action is granted only at the versions listed for that asset."""
        tokens = {}
        g = self._grants.setdefault(run_id, set())
        for a in assets:
            for act in actions:
                for v in ((versions or {}).get(a, []) if act in VERSIONED_ACTIONS else [""]):
                    g.add((a, act, v))
                    tokens[f"{a}|{act}|{v}"] = self.token(run_id, a, act, v)
        return tokens

    def token(self, run_id: str, asset: str, action: str, version: str = "") -> str:
        return hmac.new(self._key, f"{run_id}|{asset}|{action}|{version}".encode(), hashlib.sha256).hexdigest()[:32]

    def check(self, token: str, run_id: str, asset: str, action: str, version: str = "") -> tuple[bool, str]:
        if run_id in self._revoked:
            return False, f"run {run_id} has ended or been halted; write access revoked"
        if (asset, action, version) not in self._grants.get(run_id, set()):
            what = f"{action} on {asset}" + (f" to {version}" if version else "")
            return False, f"{what} is not part of an approved wave for run {run_id}"
        if not token or not hmac.compare_digest(token, self.token(run_id, asset, action, version)):
            return False, "invalid approval token"
        return True, "ok"

    def revoke_grants(self, run_id: str) -> None:
        """End an approval scope: drop the run's grants (the next scope is granted on its own approval)."""
        self._grants.pop(run_id, None)

    def revoke_run(self, run_id: str) -> None:
        self._revoked.add(run_id)
        self._grants.pop(run_id, None)

    def reinstate_run(self, run_id: str) -> None:
        self._revoked.discard(run_id)
