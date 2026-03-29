"""
Policy engine: evaluates (tool, tag, endpoint, phase, target) → (allow | block, reason).

Decision flow:
  1. Scope check  – is the target host in allowed_hosts?
  2. Rule check   – does any rule block this (tool, tag, endpoint_category, phase)?
  3. Default      – allow if nothing matched.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Endpoint path fragments that define each category.
_ENDPOINT_PATTERNS: dict[str, list[str]] = {
    "auth": ["/login", "/signin", "/logout", "/auth", "/oauth", "/token", "/password", "/session", "/sso"],
    "api": ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc"],
    "admin": ["/admin", "/dashboard", "/manage", "/console", "/internal", "/staff"],
    "static": ["/static/", "/assets/", "/public/", ".js", ".css", ".png", ".jpg", ".svg", ".woff"],
}

VALID_TAGS = {"safe", "disruptive"}
VALID_PHASES = {"recon", "scan", "fuzz", "exploit"}


@dataclass
class PolicyContext:
    """Everything the engine needs to make a decision."""
    tool: str
    tag: str = "safe"
    endpoint: Optional[str] = None
    phase: Optional[str] = None
    target: Optional[str] = None

    def __post_init__(self) -> None:
        if self.tag not in VALID_TAGS:
            raise ValueError(f"tag must be one of {VALID_TAGS}, got {self.tag!r}")
        if self.phase is not None and self.phase not in VALID_PHASES:
            raise ValueError(f"phase must be one of {VALID_PHASES}, got {self.phase!r}")


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    context: Optional[PolicyContext] = None

    def __bool__(self) -> bool:
        return self.allowed

    def as_dict(self) -> dict:
        ctx = self.context
        return {
            "action": "allow" if self.allowed else "block",
            "reason": self.reason,
            "tool": ctx.tool if ctx else None,
            "tag": ctx.tag if ctx else None,
            "endpoint": ctx.endpoint if ctx else None,
            "phase": ctx.phase if ctx else None,
            "target": ctx.target if ctx else None,
        }


def _classify_endpoint(endpoint: str) -> str:
    """Return the category name for an endpoint path, or 'unknown'."""
    ep = endpoint.lower()
    for category, patterns in _ENDPOINT_PATTERNS.items():
        if any(p in ep for p in patterns):
            return category
    return "unknown"


class PolicyEngine:
    """
    Loads a policy JSON file and evaluates PolicyContext objects.

    Policy file schema::

        {
          "allowed_hosts": ["example.com"],
          "rules": [
            {
              "tool": "ffuf",
              "blocked_tags": ["disruptive"],
              "blocked_endpoints": ["auth"],
              "blocked_phases": ["exploit"],
              "allowed_endpoints": ["static"],
              "reason": "Fuzzing too aggressive"
            }
          ]
        }

    Rule fields (all optional except ``tool``):

    * ``blocked_tags``      – block when context tag is in this list.
    * ``blocked_endpoints`` – block when classified endpoint category is in this list.
    * ``blocked_phases``    – block when phase is in this list.
    * ``allowed_endpoints`` – override: if endpoint category is in this list the
                              rule does *not* block even when tag/phase would.
    * ``reason``            – human-readable explanation surfaced on block.
    """

    def __init__(self, policy_path: str | Path) -> None:
        self.policy_path = Path(policy_path)
        self._policy: dict = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Re-read the policy file from disk."""
        self._load()

    def is_allowed(self, ctx: PolicyContext | dict) -> PolicyDecision:
        """
        Evaluate a PolicyContext and return a PolicyDecision.

        Args:
            ctx: A PolicyContext (or a dict that will be converted to one).

        Returns:
            PolicyDecision with ``allowed`` True/False and a ``reason`` string.
        """
        if isinstance(ctx, dict):
            ctx = PolicyContext(**ctx)

        if ctx.target:
            decision = self._check_scope(ctx.target)
            if not decision.allowed:
                self._audit(decision)
                return decision

        decision = self._check_rules(ctx)
        self._audit(decision)
        return decision

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with open(self.policy_path) as fh:
            self._policy = json.load(fh)

    def _check_scope(self, target: str) -> PolicyDecision:
        allowed_hosts: list[str] = self._policy.get("allowed_hosts", [])
        if not allowed_hosts:
            return PolicyDecision(True, "No host restrictions defined")
        for host in allowed_hosts:
            if target == host or target.endswith(f".{host}"):
                return PolicyDecision(True, f"{target} is in scope")
        return PolicyDecision(False, f"{target} is out of scope")

    def _check_rules(self, ctx: PolicyContext) -> PolicyDecision:
        rules: list[dict] = self._policy.get("rules", [])
        endpoint_category = _classify_endpoint(ctx.endpoint) if ctx.endpoint else None

        for rule in rules:
            if rule.get("tool") != ctx.tool:
                continue

            reason = rule.get("reason", f"blocked by rule for {ctx.tool}")

            # allowed_endpoints acts as a full exemption for this rule.
            allowed_endpoints: list[str] = rule.get("allowed_endpoints", [])
            if allowed_endpoints and endpoint_category in allowed_endpoints:
                continue

            # Each of blocked_tags / blocked_endpoints / blocked_phases is an
            # independent OR condition: the rule fires if ANY condition matches.
            if ctx.tag in rule.get("blocked_tags", []):
                return PolicyDecision(False, reason, ctx)

            if endpoint_category and endpoint_category in rule.get("blocked_endpoints", []):
                return PolicyDecision(False, reason, ctx)

            if ctx.phase and ctx.phase in rule.get("blocked_phases", []):
                return PolicyDecision(False, reason, ctx)

        return PolicyDecision(True, "Permitted by policy", ctx)

    def _audit(self, decision: PolicyDecision) -> None:
        entry = decision.as_dict()
        if decision.allowed:
            logger.info("ALLOW tool=%s tag=%s endpoint=%s phase=%s target=%s",
                        entry["tool"], entry["tag"], entry["endpoint"],
                        entry["phase"], entry["target"])
        else:
            logger.warning("BLOCK tool=%s tag=%s endpoint=%s phase=%s target=%s reason=%r",
                           entry["tool"], entry["tag"], entry["endpoint"],
                           entry["phase"], entry["target"], entry["reason"])
