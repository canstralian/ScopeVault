"""Tests for the scope validator."""
import json
import pytest
from pathlib import Path

from scopevault.scope import ScopeValidator, _extract_host, _wildcard_match


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestExtractHost:
    def test_bare_hostname(self):
        assert _extract_host("example.com") == "example.com"

    def test_url_https(self):
        assert _extract_host("https://example.com/path") == "example.com"

    def test_url_http(self):
        assert _extract_host("http://sub.example.com:8080/x") == "sub.example.com"

    def test_hostname_with_port(self):
        assert _extract_host("example.com:443") == "example.com"


class TestWildcardMatch:
    def test_exact_match(self):
        assert _wildcard_match("example.com", "example.com")

    def test_subdomain_of_bare_pattern(self):
        assert _wildcard_match("api.example.com", "example.com")

    def test_deep_subdomain_of_bare_pattern(self):
        assert _wildcard_match("a.b.example.com", "example.com")

    def test_different_domain_no_match(self):
        assert not _wildcard_match("evil.com", "example.com")

    def test_wildcard_pattern_subdomain(self):
        assert _wildcard_match("api.example.com", "*.example.com")

    def test_wildcard_pattern_bare_domain_no_match(self):
        # *.example.com should NOT match example.com itself
        assert not _wildcard_match("example.com", "*.example.com")

    def test_wildcard_pattern_deep_subdomain_no_match(self):
        # *.example.com matches only one level
        assert not _wildcard_match("a.b.example.com", "*.example.com")


# ---------------------------------------------------------------------------
# ScopeValidator
# ---------------------------------------------------------------------------

@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    data = {"allowed_hosts": ["example.com", "*.staging.example.com"], "rules": []}
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(data))
    return p


@pytest.fixture
def validator(policy_file: Path) -> ScopeValidator:
    return ScopeValidator(policy_file)


class TestInScope:
    def test_exact_host(self, validator):
        assert validator.in_scope("example.com")

    def test_subdomain(self, validator):
        assert validator.in_scope("api.example.com")

    def test_wildcard_subdomain(self, validator):
        assert validator.in_scope("dev.staging.example.com")

    def test_out_of_scope(self, validator):
        assert not validator.in_scope("evil.com")

    def test_url_in_scope(self, validator):
        assert validator.in_scope("https://api.example.com/endpoint")

    def test_url_out_of_scope(self, validator):
        assert not validator.in_scope("https://notexample.com/path")


class TestAddRemove:
    def test_add_new_host(self, validator, policy_file):
        validator.add("newhost.com")
        assert validator.in_scope("newhost.com")
        data = json.loads(policy_file.read_text())
        assert "newhost.com" in data["allowed_hosts"]

    def test_add_duplicate_is_noop(self, validator):
        original = validator.list_hosts()
        validator.add("example.com")
        assert validator.list_hosts() == original

    def test_remove_existing(self, validator, policy_file):
        result = validator.remove("example.com")
        assert result is True
        assert not validator.in_scope("example.com")
        data = json.loads(policy_file.read_text())
        assert "example.com" not in data["allowed_hosts"]

    def test_remove_nonexistent(self, validator):
        result = validator.remove("nothere.com")
        assert result is False

    def test_list_hosts(self, validator):
        hosts = validator.list_hosts()
        assert "example.com" in hosts
        assert "*.staging.example.com" in hosts


class TestNoAllowedHosts:
    def test_empty_policy_in_scope(self, tmp_path: Path):
        p = tmp_path / "empty.json"
        p.write_text(json.dumps({"allowed_hosts": [], "rules": []}))
        v = ScopeValidator(p)
        # Empty list means nothing is in scope
        assert not v.in_scope("example.com")


class TestMissingFile:
    def test_missing_file_creates_empty_state(self, tmp_path: Path):
        v = ScopeValidator(tmp_path / "nonexistent.json")
        assert v.list_hosts() == []

    def test_add_creates_file(self, tmp_path: Path):
        p = tmp_path / "new.json"
        v = ScopeValidator(p)
        v.add("example.com")
        assert p.exists()
        assert v.in_scope("example.com")


class TestReload:
    def test_reload_reflects_external_changes(self, tmp_path: Path):
        p = tmp_path / "p.json"
        p.write_text(json.dumps({"allowed_hosts": ["a.com"], "rules": []}))
        v = ScopeValidator(p)
        assert v.in_scope("a.com")

        p.write_text(json.dumps({"allowed_hosts": ["b.com"], "rules": []}))
        v.reload()
        assert not v.in_scope("a.com")
        assert v.in_scope("b.com")
