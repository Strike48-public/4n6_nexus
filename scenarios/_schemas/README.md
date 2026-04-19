# Scenario Schemas

## scenario.yaml

Every scenario directory contains a `scenario.yaml` manifest. This is the single source of truth for:

- Scenario identity (name, tier, category, difficulty)
- Source provenance (provider, URL, license)
- Evidence files (paths, sizes, SHA-256 hashes, download URLs)
- Ground truth (expected findings, required precision/recall)
- Investigative questions

See [`scenario.yaml`](scenario.yaml) for the reference schema with inline documentation.

## Discovery

The test harness discovers scenarios by globbing:

```
scenarios/**/scenario.yaml
```

Adding a new scenario requires no code changes — drop a directory with a manifest and it is picked up automatically.

## Integrity

- `sha256` in `evidence[].sha256` is authoritative. Download scripts verify after fetch.
- `size_bytes` is a fast pre-check (catches truncated downloads).
- `download_url` is a *backup* — the repo aims to be offline-usable once evidence is local.
