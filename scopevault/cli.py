"""
ScopeVault CLI

Usage examples::

    # Run ffuf with policy enforcement
    scopevault run ffuf --target api.example.com --tag disruptive \
        --endpoint /api/users --phase fuzz -- -u https://api.example.com/api/users/FUZZ -w wordlist.txt

    # Manage in-scope hosts
    scopevault scope add example.com
    scopevault scope remove example.com
    scopevault scope list

    # Inspect the active policy
    scopevault policy show
    scopevault policy validate
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import click

from .policy import PolicyContext, PolicyEngine, VALID_PHASES, VALID_TAGS
from .scope import ScopeValidator

DEFAULT_POLICY = Path("policies/default.json")


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

class _State:
    def __init__(self, policy_path: Path) -> None:
        self.policy_path = policy_path
        self._engine: PolicyEngine | None = None
        self._scope: ScopeValidator | None = None

    @property
    def engine(self) -> PolicyEngine:
        if self._engine is None:
            self._engine = PolicyEngine(self.policy_path)
        return self._engine

    @property
    def scope(self) -> ScopeValidator:
        if self._scope is None:
            self._scope = ScopeValidator(self.policy_path)
        return self._scope


pass_state = click.make_pass_decorator(_State)


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.option(
    "--policy",
    "policy_path",
    default=str(DEFAULT_POLICY),
    show_default=True,
    envvar="SCOPEVAULT_POLICY",
    help="Path to the policy JSON file.",
)
@click.pass_context
def cli(ctx: click.Context, policy_path: str) -> None:
    """ScopeVault – scope-aware policy enforcement for bug bounty tooling."""
    ctx.obj = _State(Path(policy_path))


# ---------------------------------------------------------------------------
# `run` – execute a tool after policy check
# ---------------------------------------------------------------------------

@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("tool")
@click.option("--target", required=True, help="Target hostname (must be in scope).")
@click.option(
    "--tag",
    default="safe",
    show_default=True,
    type=click.Choice(sorted(VALID_TAGS)),
    help="Risk tag for this execution.",
)
@click.option("--endpoint", default=None, help="Endpoint path being targeted (e.g. /api/login).")
@click.option(
    "--phase",
    default=None,
    type=click.Choice(sorted(VALID_PHASES)),
    help="Attack phase.",
)
@click.argument("tool_args", nargs=-1, type=click.UNPROCESSED)
@pass_state
def run(
    state: _State,
    tool: str,
    target: str,
    tag: str,
    endpoint: str | None,
    phase: str | None,
    tool_args: tuple[str, ...],
) -> None:
    """Run TOOL after verifying it is permitted by the active policy.

    Any arguments after -- are forwarded directly to TOOL.

    \b
    Examples:
      scopevault run nuclei --target example.com --tag safe --phase scan -- -u https://example.com
      scopevault run ffuf   --target example.com --tag disruptive --endpoint /login --phase fuzz \\
                            -- -u https://example.com/loginFUZZ -w words.txt
    """
    ctx = PolicyContext(tool=tool, tag=tag, target=target, endpoint=endpoint, phase=phase)
    decision = state.engine.is_allowed(ctx)

    if not decision.allowed:
        click.echo(click.style(f"[BLOCKED] {decision.reason}", fg="red"), err=True)
        _print_decision_detail(decision, err=True)
        sys.exit(1)

    click.echo(click.style(f"[ALLOWED] {decision.reason}", fg="green"))

    if tool_args:
        cmd = [tool, *tool_args]
        click.echo(f"  -> {' '.join(cmd)}")
        result = subprocess.run(cmd)
        sys.exit(result.returncode)


# ---------------------------------------------------------------------------
# `scope` sub-group
# ---------------------------------------------------------------------------

@cli.group()
def scope() -> None:
    """Manage in-scope hosts in the active policy file."""


@scope.command("add")
@click.argument("host_pattern")
@pass_state
def scope_add(state: _State, host_pattern: str) -> None:
    """Add HOST_PATTERN to the allowed hosts list.

    Supports wildcards: *.example.com
    """
    if not state.policy_path.exists():
        _bootstrap_policy(state.policy_path)
    state.scope.add(host_pattern)
    click.echo(f"Added {host_pattern!r} to {state.policy_path}")


@scope.command("remove")
@click.argument("host_pattern")
@pass_state
def scope_remove(state: _State, host_pattern: str) -> None:
    """Remove HOST_PATTERN from the allowed hosts list."""
    removed = state.scope.remove(host_pattern)
    if removed:
        click.echo(f"Removed {host_pattern!r} from {state.policy_path}")
    else:
        click.echo(f"{host_pattern!r} was not in the scope list.", err=True)
        sys.exit(1)


@scope.command("list")
@pass_state
def scope_list(state: _State) -> None:
    """List all in-scope host patterns."""
    hosts = state.scope.list_hosts()
    if not hosts:
        click.echo("No hosts in scope.")
        return
    for h in hosts:
        click.echo(f"  {h}")


# ---------------------------------------------------------------------------
# `policy` sub-group
# ---------------------------------------------------------------------------

@cli.group()
def policy() -> None:
    """Inspect the active policy."""


@policy.command("show")
@pass_state
def policy_show(state: _State) -> None:
    """Print the current policy as formatted JSON."""
    with open(state.policy_path) as fh:
        data = json.load(fh)
    click.echo(json.dumps(data, indent=2))


@policy.command("validate")
@pass_state
def policy_validate(state: _State) -> None:
    """Validate the policy file structure."""
    errors: list[str] = []
    try:
        with open(state.policy_path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        click.echo(click.style(f"Policy file not found: {state.policy_path}", fg="red"), err=True)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        click.echo(click.style(f"Invalid JSON: {exc}", fg="red"), err=True)
        sys.exit(1)

    for i, rule in enumerate(data.get("rules", [])):
        if "tool" not in rule:
            errors.append(f"Rule #{i}: missing required field 'tool'")
        for tag in rule.get("blocked_tags", []):
            if tag not in VALID_TAGS:
                errors.append(f"Rule #{i} ({rule.get('tool')}): unknown tag {tag!r}")
        for phase in rule.get("blocked_phases", []):
            if phase not in VALID_PHASES:
                errors.append(f"Rule #{i} ({rule.get('tool')}): unknown phase {phase!r}")

    if errors:
        for e in errors:
            click.echo(click.style(f"  ERROR: {e}", fg="red"), err=True)
        sys.exit(1)

    click.echo(click.style("Policy is valid.", fg="green"))
    click.echo(f"  {len(data.get('allowed_hosts', []))} host(s) in scope")
    click.echo(f"  {len(data.get('rules', []))} rule(s) defined")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_decision_detail(decision, err: bool = False) -> None:
    d = decision.as_dict()
    click.echo(
        f"  tool={d['tool']}  tag={d['tag']}  endpoint={d['endpoint']}  "
        f"phase={d['phase']}  target={d['target']}",
        err=err,
    )


def _bootstrap_policy(path: Path) -> None:
    """Create a minimal policy file if none exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    skeleton = {"allowed_hosts": [], "rules": []}
    with open(path, "w") as fh:
        json.dump(skeleton, fh, indent=2)
        fh.write("\n")
    click.echo(f"Created new policy file at {path}")


if __name__ == "__main__":
    cli()
