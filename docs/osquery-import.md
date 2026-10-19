# Import saved osquery host identity rows

The offline adapter reads a saved JSON array with exactly `hostname` and `uuid` in
each row. It never launches osquery, reads the current machine's inventory, starts a
daemon, connects to a host, or submits remediation.

The input shape corresponds to a JSON export of:

```sql
SELECT hostname, uuid FROM system_info;
```

The upstream [system_info table definition](https://github.com/osquery/osquery/blob/master/specs/system_info.table)
defines these columns. The [osquery shell flags](https://github.com/osquery/osquery/blob/master/docs/wiki/installation/cli-flags.md)
document JSON output. These references were checked on October 18, 2026. The commands
below use a synthetic saved export; no osquery execution is claimed.

## Reproduce the import

From the repository root, using only Python's standard library:

```bash
python -m engine.discovery.osquery_collector examples/osquery-system-info.json \
  --scope synthetic --output /tmp/zero-shadow-osquery-assets.json
```

Use a fresh output path. It contains fixture schema version 1, source
`osquery-system-info`, one host named `checkout.example.test`, and source record ID
`11111111-2222-4333-8444-555555555555`. The `import_metadata.input_sha256` digest
identifies the exact saved input bytes. The source fixture must be kept separately
to reproduce the import; a digest does not authenticate its origin.

The converter canonicalizes UUID spelling, lowercases hostnames, removes a trailing
hostname dot, and sorts by UUID. It adds no IP addresses, cloud identity, ownership
tags, exposure claims, or vulnerability findings.

## Use the existing workflow

Inspect a correlated inventory directly, without editing a workflow spec:

```bash
python -m engine.discovery.osquery_collector examples/osquery-system-info.json \
  --scope synthetic --format inventory
```

The report has `report_type: osquery-inventory`, `observation_count: 1`,
`asset_count: 1`, a stable asset ID, correlation keys, and the retained observation.
`input_sha256` covers the exact export bytes. Two UUID claims sharing an FQDN merge
under the existing graph rule, with both observations retained; distinct FQDNs remain
separate. This is source-claimed identity, not attestation. No risk, ownership,
exposure, or vulnerability finding is inferred. Use `--output` for a new private
report file. Inventory reports are not fixture input; the default `--format fixture`
continues to produce the workflow-compatible contract.

The default fixture output can be loaded by `load_fixture` and correlated by the existing asset graph.
For an explicitly authorized evidence workflow, make a local workflow-spec copy and
set its `asset_fixture` to the converted file, relative to that spec. Keep all files
inside the CLI's explicit `--allowed-root`. Supply independently reviewed finding
evidence and the appropriate ownership directory. Do not reuse the synthetic
high-severity finding as a claim about a real host.

The importer tests exercise this connection with the existing synthetic finding,
all six workflow checkpoints, SQLite persistence, and read-only reconstruction.
With no ownership tags, that exercise records `status: unmatched` and `team_id: null`.
There is no invented owner and no implied vulnerability assessment from system_info.

## Retain discovery before any assessment

The workflow needs independent finding evidence. When that evidence does not exist,
use discovery-only storage instead of filling in a synthetic vulnerability:

```bash
python -m database.inventory_cli examples/osquery-system-info.json --scope synthetic \
  --observed-at 2026-10-19T00:00:00Z --output /tmp/zero-shadow-inventory.sqlite
python -m database.evidence_reader_cli /tmp/zero-shadow-inventory.sqlite \
  --asset-id asset-752c9c1b37e66798 --inventory
```

The first command validates and correlates the export, commits assets and observations
in one SQLite transaction, closes the database, and publishes a complete new file with
0600 permissions on POSIX. No schema migration is needed. It prints asset IDs and the
exact input digest. It now retains an append-only import receipt containing that
digest, claimed scope, UTC observation time, asset IDs, and observation count inside
the same published database. The supplied timezone-aware
observation time and scope are caller claims, not independently verified.

The reader opens SQLite read-only. `--inventory` permits empty finding, ownership,
and plan arrays while retaining observation checks and the snapshot digest. Without
that explicit option, the existing decision-bundle requirements are unchanged. An
empty array means no decision was retained, not that a host was checked and found safe.

Each import creates a separate database, never updates an existing one. Duplicate
observation identities roll back the batch. Existing output files are preserved,
including a concurrently created destination. Temporary databases are cleaned on
ordinary failures. Parent directories must be trusted. Hard links are required and
directory crash durability is not established; this is not a multi-run inventory
service. Real inventory identifiers and exported snapshots can be sensitive. Keep
files outside Git, and protect any stdout redirection yourself.
For an exported snapshot file, the reader's `--output NEW_FILE` now uses the same
complete private exclusive publisher as the importer instead of a normal text write.

Reconcile the receipt and retained observations:

```bash
python -m database.inventory_receipt /tmp/zero-shadow-inventory.sqlite \
  --export examples/osquery-system-info.json
```

The receipt includes a canonical SHA-256 digest. The reader checks it, asset IDs,
observation count, source, scope, and time against stored rows. With `--export`, it
also checks the exact input-byte digest and regenerates correlated observations to
compare payloads and IDs. The example returns `status: consistent` and
`original_export_checked: true`. Without `--export`, that field is false; no claim is
made that the original file was checked. Even JSON whitespace changes in the export
fail the exact-byte check. The reader opens an owned or trusted local database
read-only and emits no original export bytes.

Older inventory databases lack this receipt table and are rejected by this command;
their existing inventory snapshots still work. Re-import the retained original into
a new database rather than editing old evidence. The base evidence schema remains
version 1; the inventory-only receipt is a versioned optional extension. Append-only
triggers and hashes do not protect against a privileged database writer replacing
rows, triggers, and digests together. This is consistency checking, not authentication,
attestation, proof of scan completeness, or credential-free certification.

## Compare two discovery imports

Use fresh output paths for both synthetic observations:

```bash
python -m database.inventory_cli examples/osquery-system-info.json --scope synthetic \
  --observed-at 2026-10-19T00:00:00Z --output /tmp/zero-shadow-inventory-base.sqlite
python -m database.inventory_cli examples/osquery-system-info-expanded.json --scope synthetic \
  --observed-at 2026-10-19T01:00:00Z --output /tmp/zero-shadow-inventory-current.sqlite
python -m database.inventory_diff_cli /tmp/zero-shadow-inventory-base.sqlite \
  /tmp/zero-shadow-inventory-current.sqlite
```

Expect counts `base_assets: 1`, `current_assets: 2`, `added: 1`, `shared: 1`,
`not_observed: 0`, and `changed_shared: 0`. The expanded fixture adds one fabricated
worker identity. Dates belong to the synthetic exercise, not a live discovery run.

The comparer opens both owned or trusted local databases read-only, reconciles each
receipt with its stored rows, and requires matching source and claimed scope. Current
observation time cannot precede the base. Equal times are allowed. The caller must
select imports for the same authorized population; matching scope labels do not prove
that two exports cover the same fleet or permission boundary.

Added and not-observed IDs describe these two source-claimed inventories only.
Absence does not prove a machine was deleted, remediated, or even included in both
collections. Shared-identity comparison ignores import timestamps and compares
retained payloads and asset metadata instead. Different byte digests can reflect only
formatting, so `source_bytes_changed` is separate from identity changes. Changes to
correlation keys can change an asset ID; this is not attestation of physical identity
or an automatic host-rename match. No vulnerability, risk, owner, or action is inferred.

The report includes receipt and recorded input digests, times, counts, and sorted IDs,
not raw observations or hostnames. It does not reopen original exports; use the
receipt command with `--export` separately for that check. Corrupt or incompatible
receipts, legacy databases without receipts, reversed time, and read errors exit 2
with no partial success document. `--output NEW_FILE` uses private exclusive JSON
publication; otherwise stdout privacy is the caller's responsibility. Hashes and
receipt consistency do not prevent privileged evidence replacement.

## Limits and failure behavior

- Scope must be explicitly `synthetic`, `owned`, or `authorized`. This is a caller
  assertion, not proof of permission.
- Input must be a regular local UTF-8 file, at most 4 MiB, containing 1 to 10,000 rows.
- Rows must contain exactly two string fields: `hostname` and `uuid`. Full-table
  exports, scheduled-event envelopes, and extra hardware or personal fields fail.
- Hostnames must use ASCII DNS-style labels. UUIDs must parse as UUID values and
  cannot be all zeroes, all ones, or repeated within the same export.
- UUIDs are source claims, not attested identities. Cloned or spoofed identifiers can
  still mislead correlation. The existing graph also correlates shared FQDN claims;
  importing a UUID does not replace that rule.
- A new output file is private on POSIX and published only after the complete JSON
  is written. Existing paths are never replaced. Local hard-link support is required;
  crash durability is not established. Validation failures exit 2 without a success
  document. Without `--output`, JSON goes to stdout, so any redirection is your
  responsibility to keep private.

Keep real hostnames, identifiers, exports, and converted files outside Git. AWS and
network discovery remain placeholders. Live osquery collection is not implemented.
