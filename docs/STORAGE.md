# Session storage and cross-PC workflow

Raw JSONL is the archival source of truth. A session bundle is immutable after finalization. Manifests are authoritative; catalogs and reports are rebuildable.

## Bundle layout

```text
sessions/
  2026/10/28/
    20261028T124255Z__vm-win11-01__login__iter01__a1b2c3d4/
      manifest.json
      environment.json
      notes.md
      events.jsonl
      events.jsonl.1
      summary.json
      coverage.json
      sensor-usage.json
      derived/
        census.json
      checksums.json
      bundle.sha256
```

`manifest.json` carries the labels, client/build fingerprints, configuration, sensitivity, parts, record count, and chain head. `checksums.json` carries per-part SHA-256 and the bundle hash. `bundle.sha256` is a convenience copy.

## Workflow

1. Record to local disk:
   ```bat
   msmon-agent.exe --client "C:\Nexon\Library\maplestorycw" ^
       --log-dir "C:\msmon-sessions" --session-label "login-01" ^
       --scenario login --phase steady --iteration 1 ^
       --machine-label "vm-win11-01"
   ```
2. Stop the collector normally. The agent writes `summary.json`, `session_meta.json`, and (with the coverage build) `coverage.json`.
3. Finalize:
   ```bat
   python tools\session_pack.py "C:\msmon-sessions\<bundle>"
   ```
   This verifies the chain, writes census/environment/notes, validates the schema, and creates `<bundle>.zip`.
4. Explicitly copy/upload the zip or directory to the chosen shared store.
5. Re-run `python tools\validate_schema.py --session <bundle>` and, if needed, `python tools\verify_log.py <parts>` on the destination.
6. Compare sessions:
   ```bat
   python tools\compare_sessions.py <bundle-a> <bundle-b>
   ```
7. Build the optional local catalog when the number of sessions makes file scanning slow:
   ```bat
   python tools\index_sessions.py --root C:\msmon-sessions --db C:\msmon-sessions\catalog.sqlite
   ```
8. Create a redacted derived bundle for sharing:
   ```bat
   python tools\redact_session.py <bundle> --no-compress
   ```
   The raw bundle is never modified; the redacted copy gets a new chain and manifest.

## Transfer policy

Bundles can contain registry values, hardware identifiers, paths, command lines, DNS names, and WMI query text. They are **not** uploaded automatically.

- Keep `sensitivity=payload` and `sensitivity=secrets` bundles in an access-controlled store.
- `--no-payloads` produces `sensitivity=metadata`; prefer it for broad sharing.
- Never record directly into a live-synced folder. Finalize locally, then copy the immutable zip.
- Do not sync a writable catalog or a live event file between PCs.

### Optional shared stores

| Store | Use when |
|---|---|
| OneDrive/SharePoint folder | small total volume, one or two testers |
| S3-compatible (R2/B2/S3) via `rclone`/`aws s3 cp` | large/parallel workloads, long retention |
| git-annex/DVC | small fixtures only; not raw multi-GB sessions |

## Sizing

A measured session: 325,259 records, 241 MB, 119 seconds, ~740 B/record, peak 54,618 records/s. A 30-minute capture is roughly 3-5 GB raw and 300-600 MB compressed. Budget for the raw bundle plus one compressed copy.

## Retention

- Raw bundles: 90 days by default, configurable.
- Derived census/coverage/report: may be retained longer.
- Redacted bundles: separate derived copies; never replace the raw original.
- `sessions/` and `*.jsonl` are excluded from git.

## Integrity

- `verify_log.py` checks the record chain and payload chunking.
- `session_pack.py` runs it before writing the manifest.
- `checksums.json` records every part hash; `compare_sessions.py` re-verifies before comparing.
- Keep `checksums.json` (or the final `bundle.sha256`) separately if later tamper detection matters.
