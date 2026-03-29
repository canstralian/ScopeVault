"""Tests for the policy engine."""
import json
import pytest
from pathlib import Path

from scopevault.policy import PolicyEngine, PolicyContext, PolicyDecision, _classify_endpoint


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    data = {
        "allowed_hosts": ["example.com", "*.example.com"],
        "rules": [
            {
                "tool": "ffuf",
                "blocked_tags": ["disruptive"],
                "blocked_endpoints": ["auth"],
                "reason": "Fuzzing auth endpoints is blocked",
            },
            {
                "tool": "nuclei",
                "blocked_phases": ["exploit"],
                "allowed_endpoints": ["static"],
                "reason": "nuclei exploit mode blocked except on static",
            },
            {
                "tool": "hydra",
                "blocked_tags": ["safe", "disruptive"],
                "reason": "Brute-force always blocked",
            },
        ],
    }
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(data))
    return p


@pytest.fixture
def engine(policy_file: Path) -> PolicyEngine:
    return PolicyEngine(policy_file)


# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------

class TestClassifyEndpoint:
    def test_auth_login(self):
        assert _classify_endpoint("/login") == "auth"

    def test_auth_oauth(self):
        assert _classify_endpoint("/oauth/token") == "auth"

    def test_api(self):
        assert _classify_endpoint("/api/v2/users") == "api"

    def test_admin(self):
        assert _classify_endpoint("/admin/dashboard") == "admin"

    def test_static_js(self):
        assert _classify_endpoint("/assets/app.js") == "static"

    def test_unknown(self):
        assert _classify_endpoint("/search") == "unknown"


# ---------------------------------------------------------------------------
# Scope checks
# ---------------------------------------------------------------------------

class TestScopeCheck:
    def test_exact_host_allowed(self, engine):
        d = engine.is_allowed(PolicyContext("nmap", target="example.com"))
        assert d.allowed

    def test_subdomain_allowed(self, engine):
        d = engine.is_allowed(PolicyContext("nmap", target="api.example.com"))
        assert d.allowed

    def test_out_of_scope_blocked(self, engine):
        d = engine.is_allowed(PolicyContext("nmap", target="evil.com"))
        assert not d.allowed
        assert "out of scope" in d.reason

    def test_no_target_skips_scope_check(self, engine):
        d = engine.is_allowed(PolicyContext("nmap"))
        assert d.allowed


# ---------------------------------------------------------------------------
# Rule: blocked_tags
# ---------------------------------------------------------------------------

class TestBlockedTags:
    def test_ffuf_disruptive_blocked(self, engine):
        d = engine.is_allowed(PolicyContext("ffuf", tag="disruptive", target="example.com"))
        assert not d.allowed
        assert "Fuzzing" in d.reason

    def test_ffuf_safe_allowed(self, engine):
        d = engine.is_allowed(PolicyContext("ffuf", tag="safe", target="example.com"))
        assert d.allowed

    def test_hydra_safe_blocked(self, engine):
        d = engine.is_allowed(PolicyContext("hydra", tag="safe", target="example.com"))
        assert not d.allowed

    def test_hydra_disruptive_blocked(self, engine):
        d = engine.is_allowed(PolicyContext("hydra", tag="disruptive", target="example.com"))
        assert not d.allowed


# ---------------------------------------------------------------------------
# Rule: blocked_endpoints
# ---------------------------------------------------------------------------

class TestBlockedEndpoints:
    def test_ffuf_disruptive_on_auth_blocked(self, engine):
        d = engine.is_allowed(PolicyContext(
            "ffuf", tag="disruptive", target="example.com", endpoint="/login"
        ))
        assert not d.allowed

    def test_ffuf_disruptive_on_api_blocked(self, engine):
        # disruptive tag matches blocked_tags regardless of endpoint
        d = engine.is_allowed(PolicyContext(
            "ffuf", tag="disruptive", target="example.com", endpoint="/api/users"
        ))
        assert not d.allowed

    def test_ffuf_safe_on_auth_blocked(self, engine):
        # blocked_endpoints is an independent condition: auth endpoint blocks any tag
        d = engine.is_allowed(PolicyContext(
            "ffuf", tag="safe", target="example.com", endpoint="/login"
        ))
        assert not d.allowed


# ---------------------------------------------------------------------------
# Rule: blocked_phases
# ---------------------------------------------------------------------------

class TestBlockedPhases:
    def test_nuclei_exploit_phase_blocked(self, engine):
        d = engine.is_allowed(PolicyContext(
            "nuclei", tag="safe", target="example.com", phase="exploit"
        ))
        assert not d.allowed

    def test_nuclei_scan_phase_allowed(self, engine):
        d = engine.is_allowed(PolicyContext(
            "nuclei", tag="safe", target="example.com", phase="scan"
        ))
        assert d.allowed


# ---------------------------------------------------------------------------
# Rule: allowed_endpoints override
# ---------------------------------------------------------------------------

class TestAllowedEndpointsOverride:
    def test_nuclei_exploit_on_static_allowed(self, engine):
        # allowed_endpoints: ["static"] overrides blocked_phases: ["exploit"]
        d = engine.is_allowed(PolicyContext(
            "nuclei", tag="safe", target="example.com",
            endpoint="/static/app.js", phase="exploit"
        ))
        assert d.allowed


# ---------------------------------------------------------------------------
# Tool with no matching rule
# ---------------------------------------------------------------------------

class TestNoMatchingRule:
    def test_unknown_tool_allowed(self, engine):
        d = engine.is_allowed(PolicyContext("curl", tag="safe", target="example.com"))
        assert d.allowed

    def test_unknown_tool_disruptive_allowed(self, engine):
        # No rule → default allow
        d = engine.is_allowed(PolicyContext("curl", tag="disruptive", target="example.com"))
        assert d.allowed


# ---------------------------------------------------------------------------
# PolicyContext validation
# ---------------------------------------------------------------------------

class TestPolicyContextValidation:
    def test_invalid_tag_raises(self):
        with pytest.raises(ValueError, match="tag must be one of"):
            PolicyContext("ffuf", tag="unknown")

    def test_invalid_phase_raises(self):
        with pytest.raises(ValueError, match="phase must be one of"):
            PolicyContext("ffuf", phase="detonate")


# ---------------------------------------------------------------------------
# PolicyDecision helpers
# ---------------------------------------------------------------------------

class TestPolicyDecision:
    def test_bool_true(self):
        assert bool(PolicyDecision(True, "ok")) is True

    def test_bool_false(self):
        assert bool(PolicyDecision(False, "no")) is False

    def test_as_dict_action_allow(self):
        d = PolicyDecision(True, "ok", PolicyContext("ffuf", tag="safe"))
        assert d.as_dict()["action"] == "allow"

    def test_as_dict_action_block(self):
        d = PolicyDecision(False, "no", PolicyContext("ffuf", tag="safe"))
        assert d.as_dict()["action"] == "block"


# ---------------------------------------------------------------------------
# Reload
# ---------------------------------------------------------------------------

class TestReload:
    def test_reload_picks_up_changes(self, tmp_path: Path):
        p = tmp_path / "p.json"
        p.write_text(json.dumps({"allowed_hosts": ["a.com"], "rules": []}))
        eng = PolicyEngine(p)
        assert eng.is_allowed(PolicyContext("ffuf", target="a.com")).allowed

        # Now restrict
        p.write_text(json.dumps({"allowed_hosts": ["b.com"], "rules": []}))
        eng.reload()
        assert not eng.is_allowed(PolicyContext("ffuf", target="a.com")).allowed
