"""
Scope validator: manages the allowed_hosts list in a policy file and
provides helpers to check whether a target (hostname or URL) is in scope.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse


def _extract_host(target: str) -> str:
    """Return the bare hostname from a target string (hostname or URL)."""
    if "://" in target:
        return urlparse(target).hostname or target
    # Strip port if present
    return target.split(":")[0].rstrip("/")


def _wildcard_match(host: str, pattern: str) -> bool:
    """
    Match a host against a scope pattern.

    Supported patterns:
    * ``example.com``       – exact match or any subdomain
    * ``*.example.com``     – any subdomain (not bare domain)
    * ``sub.example.com``   – exact subdomain only
    """
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # Enforce exactly one subdomain level: api.example.com ✓, a.b.example.com ✗
        parent = host[len(host) - len(suffix) - 1:]  # ".example.com" portion
        subdomain = host[: len(host) - len(suffix) - 1]
        return (
            parent == f".{suffix}"
            and subdomain != ""
            and "." not in subdomain
        )
    # Bare domain: allow exact match or any subdomain
    return host == pattern or host.endswith(f".{pattern}")


class ScopeValidator:
    """
    Loads/saves allowed_hosts from a policy JSON file and checks targets.

    The policy file is only written when ``add`` or ``remove`` is called;
    ``in_scope`` is purely read-based.
    """

    def __init__(self, policy_path: str | Path) -> None:
        self.policy_path = Path(policy_path)
        self._policy: dict = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def in_scope(self, target: str) -> bool:
        """Return True if *target* matches any entry in allowed_hosts."""
        host = _extract_host(target)
        for pattern in self._policy.get("allowed_hosts", []):
            if _wildcard_match(host, pattern):
                return True
        return False

    def add(self, host_pattern: str) -> None:
        """Add *host_pattern* to allowed_hosts (no-op if already present)."""
        hosts: list[str] = self._policy.setdefault("allowed_hosts", [])
        if host_pattern not in hosts:
            hosts.append(host_pattern)
            self._save()

    def remove(self, host_pattern: str) -> bool:
        """Remove *host_pattern* from allowed_hosts. Returns True if it existed."""
        hosts: list[str] = self._policy.get("allowed_hosts", [])
        if host_pattern in hosts:
            hosts.remove(host_pattern)
            self._policy["allowed_hosts"] = hosts
            self._save()
            return True
        return False

    def list_hosts(self) -> list[str]:
        """Return a copy of the current allowed_hosts list."""
        return list(self._policy.get("allowed_hosts", []))

    def reload(self) -> None:
        self._load()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self.policy_path.exists():
            with open(self.policy_path) as fh:
                self._policy = json.load(fh)
        else:
            self._policy = {}

    def _save(self) -> None:
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.policy_path, "w") as fh:
            json.dump(self._policy, fh, indent=2)
            fh.write("\n")
