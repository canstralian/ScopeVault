# Contributing to ScopeVault

Thank you for your interest in contributing. ScopeVault is a minimal, security-sensitive tool — contributions should respect its focused scope and safety constraints.

---

## What We Welcome

- New tool integrations (recon, mapping, attack phases)
- Improvements to scope enforcement or disruptive-action guards
- Tagging logic and policy improvements
- Logging, evidence, and report enhancements
- Bug fixes and documentation updates

## What We Do Not Accept

- Weakening or removing scope enforcement (`ensure_in_scope`)
- Bypassing the disruptive-action guard (`--tag disruptive` / `--allow`)
- External Python dependencies (standard library only)
- New modules or files unless `cli.py` grows substantially beyond ~300 lines

---

## Getting Started

### Prerequisites

ScopeVault wraps external binaries. Ensure these are on your `PATH`:

```
subfinder   httpx   gau   ffuf   nuclei
```

Python 3.8+ is required. No pip packages are needed.

### Clone and explore

```bash
git clone https://github.com/canstralian/ScopeVault.git
cd ScopeVault
python cli.py --help
```

### Run a local test cycle

```bash
# Edit scope.json to add your test target
python cli.py init   --target example.com --scope scope.json
python cli.py recon  --target example.com
python cli.py map    --target example.com
python cli.py attack --target example.com --tool "echo" --extra "test"
python cli.py report --target example.com
```

There is no automated test suite. Manually verify both the happy path and failure cases (out-of-scope target, disruptive action without `--allow`).

---

## Making Changes

### Branch naming

```
claude/<short-description>     # AI-assisted changes
fix/<short-description>        # Bug fixes
feat/<short-description>       # New features
docs/<short-description>       # Documentation only
```

### Commit style

Use imperative mood, present tense. One sentence is usually enough.

```
Add wildcard subdomain matching to ensure_in_scope
Fix latest_run crash when target directory is empty
Document disruptive-action guard in CLAUDE.md
```

Reference an issue number when one exists: `Fix #42: ...`

### Code conventions

- PEP 8, functional style — no classes.
- `snake_case` for all functions and variables.
- All logic lives in `cli.py`. Do not split into modules without discussion.
- No comments unless the *why* is genuinely non-obvious.
- Error handling via specific built-in exceptions (e.g., `ValueError`, `RuntimeError`) with a descriptive message; avoid bare `Exception`.

### Security-sensitive areas

If your change touches any of the following, call it out explicitly in your PR description:

| Area | File | What to check |
|---|---|---|
| Scope enforcement | `cli.py` `ensure_in_scope` | Still raises on out-of-scope targets |
| Disruptive guard | `cli.py` `attack` | Still blocks without `--allow` |
| Shell execution | `cli.py` `run_cmd` | `shell=True` with no sanitization is a known constraint — changes must not introduce new unsanitized inputs; prefer `shlex.quote` for any new interpolation |
| Scope config | `scope.json` | `allowed_hosts` not widened unintentionally |

---

## Pull Requests

1. Fork the repository and create a branch from `main`.
2. Make your changes with clear, focused commits.
3. Test manually — cover both the golden path and the failure cases.
4. Open a PR against `main`. Describe *what* changed and *why*.
5. PRs that weaken security boundaries will not be merged.

---

## Reporting Issues

Open a GitHub issue. Include:

- The exact command you ran
- The contents of your `scope.json` (redact real targets if needed)
- The full error output
- Your OS and Python version

---

## Disclaimer

ScopeVault is intended for authorized security testing only. All contributions must be consistent with lawful, permitted use. Do not submit changes that make it easier to target systems without authorization.
