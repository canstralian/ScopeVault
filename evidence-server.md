# Evidence Server

The evidence server acts as the immutable ledger for validated reports.

## Checks enforced

1. Report hash recomputation
2. Append-only existence check
3. Audit-chain continuity check
4. Immutable filesystem write
5. Journal append

## Storage layout

```text
./audit_data/
├── journal.ndjson
└── reports/
    └── <artifact_id>/
        └── <version>/
            └── <phase>/
                └── <run_id>.json
```

## Why it matters

Without the evidence server, orchestration is only transient message passing.
With it, each accepted report becomes a durable governance event.
