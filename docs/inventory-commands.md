# Retain an inventory review from the root command

The temporary demo removes its files at the end. This walkthrough keeps a synthetic
discovery, assessment and dated queue in a new private directory so they can be
inspected and reproduced later. Use Python 3.11 or newer on POSIX from the repository
root. No optional packages, cloud credentials, services or network calls are needed.

```bash
python -m engine inventory
python -m engine inventory assess --help
```

The first command lists six tools and does not open input files. Each tool delegates
to its existing parser. Paths and arguments are not interpreted as module names or
shell commands. Existing `python -m database.MODULE` commands still work.

## Import, assess and reproduce

```bash
review_dir=$(mktemp -d)
python -m engine inventory import examples/osquery-system-info-expanded.json \
  --scope synthetic --observed-at 2026-10-23T00:00:00Z \
  --output "$review_dir/discovery.sqlite"
python -m engine inventory assess "$review_dir/discovery.sqlite" \
  examples/inventory-findings.jsonl --directory examples/ownership-directory.json \
  --export examples/osquery-system-info-expanded.json --as-of 2026-10-23 \
  --assessed-at 2026-10-23T01:00:00Z --output "$review_dir/assessment.sqlite"
python -m engine inventory verify "$review_dir/assessment.sqlite" \
  --export examples/osquery-system-info-expanded.json --require-model-binding
```

Expect status `stored` with two observations, `assessment_stored` with one supplied
finding, then `assessment_reproduced` with `model_binding.status: bound_current_model`.
The assessment is a separate database. The discovery is unchanged and is not needed
for subsequent assessment verification. Keep the exact original export and matching
trusted checkout. Dates and findings here are fixture claims, not live measurements.

For a private inventory export, use:

```bash
python -m engine inventory export "$review_dir/discovery.sqlite" \
  --export examples/osquery-system-info-expanded.json --output "$review_dir/inventory.json"
```

Export without `--output` prints the full inventory. It can contain identifiers,
hostnames and findings. Keep real outputs outside Git and private. Use `owned` or
`authorized` only for source data you are permitted to handle, and supply finding
identities that actually match the chosen inventory. Supplied associations and
ownership tags are not independently verified by these commands.

## Produce and reproduce a dated queue

For this local fixture walkthrough, record the retained database digest:

```bash
database_pin=$(python -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$review_dir/assessment.sqlite")
python -m engine inventory queue "$review_dir/assessment.sqlite" \
  --export examples/osquery-system-info-expanded.json \
  --expected-database-sha256 "$database_pin" --as-of 2026-11-16 \
  --output "$review_dir/queue.json"
```

Expect `assessment_queue_exported`, one assigned item and one changed overdue-status
item. Retain the returned `output_sha256` separately. To reproduce this exact report,
replace `RETAINED_QUEUE_SHA256` with that value:

```bash
python -m engine inventory verify-queue "$review_dir/queue.json" "$review_dir/assessment.sqlite" \
  --export examples/osquery-system-info-expanded.json \
  --expected-database-sha256 "$database_pin" \
  --expected-report-sha256 RETAINED_QUEUE_SHA256 --as-of 2026-11-16
```

Expect `assessment_queue_reproduced`. In a real handoff the recipient must obtain
both pins and the review date through an independently trusted channel. Computing
pins from untrusted received files does not authenticate those files. See
[dated queue checks](assessment-queues.md) for the full trust boundary.

All output paths must be new. A changed original, incorrect pin, stale model or
invalid date fails with exit code 2. The dispatcher preserves that exit code; it
does not skip failed checks or retry with weaker options. Retention uses closed
cooperatively managed SQLite files, not a live backup. No ticket is sent, owner
consent inferred, remediation performed or source truth established. Remove your
temporary directory when finished, after retaining any evidence you need privately.
