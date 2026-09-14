# Zero Shadow Autonomous Asset Intelligence

Zero Shadow is being built as a local-first asset inventory and risk explanation
project. The repository began as a directory skeleton. Features are marked as working
only after code and deterministic tests exist.

## Current capability

The first working slice loads explicitly scoped JSON fixtures and correlates asset
observations without contacting any network or cloud account.

It supports:

- validated source records, hostnames, IP addresses, cloud identifiers, and tags
- an explicit `synthetic`, `owned`, or `authorized` scope on every fixture batch
- deterministic correlation using source record IDs, fully qualified hostnames, and
  complete cloud resource identities
- preservation of every source observation as evidence
- stable asset IDs and output ordering

IP addresses do not cause merges by themselves. Addresses are often reassigned or
shared, so they remain evidence until another strong identifier supports correlation.

## Fixture format

```json
{
  "schema_version": 1,
  "scope": "synthetic",
  "source": "cmdb",
  "assets": [
    {
      "source_record_id": "server-1",
      "kind": "server",
      "hostname": "api.example.test",
      "ip_addresses": ["192.0.2.10"],
      "cloud_provider": "aws",
      "cloud_account": "111122223333",
      "cloud_resource_id": "i-0123456789abcdef0",
      "tags": {"owner": "security-lab"}
    }
  ]
}
```

The examples use reserved documentation ranges and synthetic identifiers.

## Run tests

From the repository root:

```bash
python -m unittest discover -s tests -v
```

## Security boundary

This milestone accepts local fixture files only. It does not enumerate DNS, query cloud
APIs, scan addresses, or authenticate to external systems. Later discovery connectors
must keep the same explicit scope checks and must be tested against mocks before any
authorized integration is considered.

## Next milestone

Add an explainable risk model that scores fixture-backed findings separately from asset
identity confidence. Risk output must include contributing factors and boundary tests.
