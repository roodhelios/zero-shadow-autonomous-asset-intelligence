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

The output can be loaded by `load_fixture` and correlated by the existing asset graph.
For an explicitly authorized evidence workflow, make a local workflow-spec copy and
set its `asset_fixture` to the converted file, relative to that spec. Keep all files
inside the CLI's explicit `--allowed-root`. Supply independently reviewed finding
evidence and the appropriate ownership directory. Do not reuse the synthetic
high-severity finding as a claim about a real host.

The importer tests exercise this connection with the existing synthetic finding,
all six workflow checkpoints, SQLite persistence, and read-only reconstruction.
With no ownership tags, that exercise records `status: unmatched` and `team_id: null`.
There is no invented owner and no implied vulnerability assessment from system_info.

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
