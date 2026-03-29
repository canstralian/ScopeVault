# Architecture Overview

The repo is structured as a controlled feedback loop rather than a flat checklist.

## Core model

- Recon expands the asset graph.
- Discovery maps entry points and parameters.
- Validation evaluates findings against policy and reproducibility rules.
- Evidence commits accepted reports into an append-only audit chain.
- Orchestration decides whether a run fails, continues, or becomes defend-eligible.

## Design intent

This replaces a linear scan-everything approach with:

`recon -> hypothesis -> test -> signal -> validate -> commit -> refine`

## Modules

### `packages/shared`
Shared contracts, hashing, and report types.

### `servers/evidence-server`
The authoritative commit point. It verifies hash integrity, append-only semantics, and chain continuity before writing to storage.

### `servers/validation-server`
Receives candidate findings, loads policy, applies validation logic, and emits verdicts.

### `host-orchestrator`
Coordinates phases and handles branching paths such as terminal fail or defend-eligible.
