# Scope Vault CLI

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

---

## Overview

Scope Vault CLI is a controlled bug bounty execution system.

It enforces:
- explicit scope boundaries
- policy-driven execution
- automatic risk classification
- structured run logging

This is not a scanner.

It is a governed attack pipeline designed to reduce noise, prevent mistakes, and increase signal.

---

## Core Model

The system is built around four layers:

```
Scope → Policy → Tagging → Execution
```

- **Scope Vault** → defines what is allowed
- **Policy Engine** → enforces program rules
- **AutoTagger** → classifies risk (safe vs disruptive)
- **CLI Engine** → executes actions with logging

---

## Features

### Scope Enforcement
- Hard validation against allowed domains
- No implicit targeting
- Prevents out-of-scope mistakes

### Policy Engine
- Blocks actions based on rules
- Tool-aware + risk-aware decisions
- Centralized control via JSON

### Automatic Tagging
- Classifies actions as `safe` or `disruptive`
- Based on tool + execution parameters
- Optional manual override

### Run-Based Execution
- Each run is isolated
- Reproducible structure
- Clean audit trail

### Logging & Observability
- Command execution logs
- Structured outputs
- Report scaffolding

---

## Installation

```bash
git clone https://github.com/Chemically-Motivated-Solutions/ScopeVault.git
cd ScopeVault
pip install -r requirements.txt  # optional if extended
```

Ensure required tools are installed:
- `subfinder`
- `httpx`
- `gau`
- `ffuf`
- `nuclei`

---

## Quick Start

### 1. Define Scope

```json
{
  "allowed_hosts": ["example.com"],
  "allow_disruptive": false
}
```

### 2. Initialize Run

```bash
python cli.py init --target example.com --scope scope.json
```

### 3. Recon (Low Noise)

```bash
python cli.py recon --target example.com
```

### 4. Map Inputs

```bash
python cli.py map --target example.com
```

### 5. Execute Attack (Policy Controlled)

```bash
python cli.py attack --target example.com --tool nuclei
```

AutoTagger will classify risk:
- `safe` → allowed
- `disruptive` → blocked (unless permitted)

### 6. Generate Report

```bash
python cli.py report --target example.com
```

---

## Example Execution Flow

```
init → recon → map → attack → report
```

Each step writes into:

```
runs/{target}/{timestamp}/
```

---

## Directory Structure

```
scope-vault/
├── cli.py
├── policy.py
├── autotag.py
├── policy.json
├── scope.json
├── runs/
│   └── example.com/
│       └── 20260329-120000/
│           ├── manifest.json
│           ├── recon.log
│           ├── map.log
│           ├── attack.log
│           └── REPORT.md
```

---

## Policy Engine Example

```json
{
  "rules": [
    {
      "tool": "ffuf",
      "blocked_tags": ["disruptive"],
      "reason": "Aggressive fuzzing blocked"
    }
  ]
}
```

---

## AutoTagging Logic

| Tool     | Behavior                        | Tag         |
|----------|---------------------------------|-------------|
| ffuf     | wordlist / concurrency detected | disruptive  |
| sqlmap   | always aggressive               | disruptive  |
| nuclei   | template scanning               | safe        |

---

## Design Philosophy

### 1. Explicit > Implicit

No guessing scope. No silent execution.

### 2. Control > Speed

Fewer requests, higher signal.

### 3. Systems > Scripts

This is a pipeline, not a collection of tools.

### 4. Safety by Default

Disruptive actions are blocked unless explicitly allowed.

---

## Roadmap

### Next Layers
- Endpoint classification (auth / API / admin)
- Context-aware tagging
- Rate limiting engine
- Evidence hashing (immutable runs)
- Attack templates (IDOR, SSRF, XSS)
- Graph-based asset modeling

---

## Contributing

Pull requests are welcome.

Focus areas:
- new policies
- tagging improvements
- tool integrations
- logging + evidence systems

---

## Disclaimer

This tool is intended for:
- authorized bug bounty programs
- permitted security testing

Do not use against targets without explicit permission.

---

## License

MIT License

---

## Final Note

Most tools execute.

Scope Vault decides whether execution should happen at all.

That distinction is the entire system.
