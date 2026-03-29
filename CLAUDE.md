# CLAUDE.md — ScopeVault

This document describes the ScopeVault codebase for AI assistants. Read this before making changes.

---

## Project Overview

ScopeVault is a minimal, scope-enforced bug bounty orchestration CLI. It wraps external security tools (`subfinder`, `httpx`, `gau`, `nuclei`, etc.), enforces target scope, and collects run artifacts (logs, reports) in a structured directory tree.

**Language**: Python 3, standard library only — no external dependencies.
**Entry point**: `cli.py` (single-file, ~100 lines)
**Config**: `scope.json` defines allowed targets.

---

## Repository Structure

```
cli.py          # Entire application — CLI parser + all command logic
scope.json      # Scope definition (allowed_hosts, allow_disruptive)
README.md       # Brief usage examples
```

**At runtime**, the tool creates:
```
runs/
└── {target}/
    └── {YYYYMMDD-HHMMSS}/    # UTC timestamp, one dir per run
        ├── manifest.json     # {"target": "...", "run_id": "..."}
        ├── recon.log         # subfinder output
        ├── map.log           # gau output
        ├── attack.log        # user-specified tool output
        └── REPORT.md         # Generated findings report
```

`runs/` is created at runtime; it is not committed.

---

## Architecture

`cli.py` follows a flat, functional style — no classes, no abstractions beyond utility functions.

### Core utility functions

| Function | Purpose |
|---|---|
| `now()` | UTC timestamp string `YYYYMMDD-HHMMSS` |
| `load_scope(path)` | Parse `scope.json` |
| `ensure_in_scope(target, scope)` | Validate target against `allowed_hosts`; raises `Exception` on failure |
| `run_cmd(cmd, log_file)` | Execute shell command, stream output to stdout and append to log |
| `latest_run(base, target)` | Return the most recent timestamped run dir for a target |

### CLI commands

All commands are registered as `argparse` subparsers. Each binds to a handler function via `set_defaults(func=...)`.

| Command | Handler | Required args | What it does |
|---|---|---|---|
| `init` | `init()` | `--target`, `--scope` | Validates scope, creates run dir, writes `manifest.json` |
| recon | recon() | --target | Runs `subfinder -d {target} -silent`, logging output to `recon.log` |
| `map` | `map_stage()` | `--target` | Runs `gau {target}`, logs to `map.log` |
| `attack` | `attack()` | `--target`, `--tool` | Runs `{tool} {extra}`, requires `--allow` if `--tag disruptive` |
| `report` | `report()` | `--target` | Writes `REPORT.md` header stub |

All commands accept `--base` (default: `runs`) to override the run directory.

### Scope enforcement

`scope.json` structure:
```json
{
  "allowed_hosts": ["example.com"],
  "allow_disruptive": false
}
```

- `ensure_in_scope()` checks `target.endswith(allowed_host)` for each entry — so `sub.example.com` matches `example.com`.
- Disruptive tools require the `--allow` flag on the `attack` command explicitly; `allow_disruptive` in `scope.json` is parsed but not currently wired into the guard logic.

### Command execution (`run_cmd`)

Uses `subprocess.Popen(cmd, shell=True, ...)` — commands are passed as raw shell strings. This means `--tool` and `--extra` values in `attack` are interpolated directly into the shell command with no sanitization.

---

## Development Workflow

### Prerequisites

Install the external tools the CLI wraps (not Python packages):
- `subfinder` — subdomain enumeration
- `httpx` — HTTP probing
- `gau` — URL collection
- `nuclei` — vulnerability scanning (or any tool passed via `--tool`)

### Running the CLI

```bash
# 1. Initialize a run (creates runs/example.com/TIMESTAMP/)
python cli.py init --target example.com --scope scope.json

# 2. Reconnaissance
python cli.py recon --target example.com

# 3. Asset mapping
python cli.py map --target example.com

# 4. Attack phase (safe tag)
python cli.py attack --target example.com --tool "nuclei" --extra "-t http/cves/"

# 5. Attack phase (disruptive — requires explicit --allow)
python cli.py attack --target example.com --tool "some-tool" --tag disruptive --allow

# 6. Generate report stub
python cli.py report --target example.com
```

### Changing scope

Edit `scope.json` directly:
```json
{
  "allowed_hosts": ["example.com", "another-target.io"],
  "allow_disruptive": false
}
```

---

## Code Conventions

- **Style**: PEP 8, functional (no classes), minimal abstractions.
- **Naming**: `snake_case` for functions and variables; lowercase for subcommand names.
- **Error handling**: Raises bare `Exception` with a descriptive message; no custom exception hierarchy.
- **No linting/formatting config** is present — use `pycodestyle`/`black` manually if needed.
- **No tests** exist in the repo. New functionality should be manually tested.
- **Single-file discipline**: All logic lives in `cli.py`. Do not split into modules unless the file grows substantially.

---

## Key Constraints for AI Assistants

1. **Scope is the security boundary** — never remove or weaken `ensure_in_scope()` checks.
2. **The disruptive guard** (`if args.tag == "disruptive" and not args.allow`) must not be bypassed or removed.
3. **`run_cmd` uses `shell=True`** — any changes that pass user-controlled strings to it must be audited for command injection.
4. **No external Python dependencies** — do not add `requirements.txt` entries or `import` third-party packages without explicit instruction.
5. **`latest_run` is order-dependent** — it sorts lexicographically; the `YYYYMMDD-HHMMSS` timestamp format is required to preserve correct ordering.
6. **`report` is a stub** — `REPORT.md` is written with only a header. Extending it to include actual findings data is an open task.

---

## Git Workflow

- Default branch: `main`
- Feature branches: `claude/<description>` convention used for AI-driven changes
- No CI/CD pipelines exist; commits go directly to branches
- Push with: `git push -u origin <branch-name>`
