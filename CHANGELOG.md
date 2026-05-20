# Changelog

All notable changes to ScopeVault are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `CONTRIBUTING.md` — contribution guidelines, branch conventions, security-sensitive areas
- `CHANGELOG.md` — this file

---

## [0.4.0] — 2026-05-20

### Added
- Release preparation script (`scripts/release.sh`) to automate version tagging and changelog coordination

### Changed
- Iterative improvements to `release.sh` across multiple commits

---

## [0.3.0] — 2026-04-10

### Added
- CodeQL analysis workflow for Python and TypeScript (`.github/workflows/codeql.yml`)
- `evidence_server.py` and `evidence-server.md` — evidence collection server and documentation
- `index.ts` — TypeScript entry point

### Changed
- Reorganized docs into structured subdirectories:
  - `docs/architecture/` — system overview
  - `docs/reference/` — roadmap
  - `docs/source-material/` — bug bounty methodology references

### Fixed
- README title formatting

---

## [0.2.0] — 2026-03-29

### Added
- Core CLI (`cli.py`) with five pipeline commands: `init`, `recon`, `map`, `attack`, `report`
- `scope.json` — scope definition with `allowed_hosts` and `allow_disruptive` fields
- Scope enforcement via `ensure_in_scope()` — raises on out-of-scope targets
- Disruptive-action guard in `attack` — requires explicit `--allow` flag for `--tag disruptive`
- Run isolation: each `init` creates a timestamped directory under `runs/{target}/`
- `manifest.json` written per run with target and run ID
- Shell command execution via `run_cmd()` with live stdout streaming and log file append
- `latest_run()` utility for resolving the most recent run directory
- `README.md` with usage examples, design philosophy, and roadmap

### Security
- `shell=True` noted as a known constraint in `run_cmd`; `--tool` and `--extra` values are not sanitized

---

## [0.1.0] — 2026-03-01

### Added
- Initial repository scaffolding
- Project documentation and architecture notes
