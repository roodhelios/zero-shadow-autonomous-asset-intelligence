# Authenticate saved collector claims before network review

Byte pins identify selected files but not which enrolled key supplied them. This
workflow verifies an Ed25519 attestation against a separately pinned, context-scoped
public policy, then reproduces the network review from the exact signed export and
roster bytes. It authenticates a key's claim, not an AWS response or physical host.

From the checkout on POSIX, with Python 3.11+ and optional
`requirements-review.txt` dependencies installed:

```bash
python -m engine.discovery.ec2_collector_attestation demo
```

The in-memory exercise generates a new ephemeral key, prepares a public policy,
signs the bundled synthetic export/roster, verifies using PyNaCl and rejects changed
export bytes. No private seed, policy, signature or operational identifier is printed
or written. Selected output:

```json
{
  "status": "ec2_collector_attestation_exercise_passed",
  "collector_signature_verified": true,
  "changed_export_rejected": true,
  "aws_source_verified": false,
  "selected_roster_matches": false
}
```

The roster mismatch is intentional: the fixture lacks expected network metadata.
A valid signature does not make a supplied claim accurate or safe. No AWS request,
database, cloud resource, scan or remediation operation occurs.

## Enroll public policy and prepare claims

The strict outer policy contains exactly `schema_version: 1`, `scope`, `account`,
`region` and `authority`. Context must equal the recipient's explicit selection.
`authority` reuses the existing history-approval policy schema with the new purpose
`zero-shadow-ec2-collector-attestation-v1`: `schema_version: 1`, `purpose`, `audience`,
`max_validity_seconds` and `keys`. Each key has `key_id`, canonical `public_key_b64`,
`state`, `not_before` and `not_after`. IDs/audiences are lowercase identifiers of
3 to 64 characters. Duplicate IDs or public keys reject. The existing policy allows
1 to 32 keys and a maximum interval of 1 second to 7 days. Choose an appropriately
short reviewed window. Existing history approval policies/domains are unchanged.

Independently establish who holds each collector key and which account/region/scope
it may claim. Retain the exact outer policy digest through a trusted channel. Keys
come from that policy, never an inline claim-supplied public key. Merely pinning an
untrusted policy does not establish enrollment. Old snapshots are not made current.

The signing API is `create_attestation(export_bytes, roster_bytes, policy_bytes,
expected_policy_sha256=..., scope=..., account=..., region=..., audience=...,
key_id=..., seed=..., captured_at=..., expires_at=..., at=...)`. It checks that a
private 32-byte seed matches an active enrolled key, validates the local inputs and
signs their exact claim. Private-key loading/export/enrollment is outside the CLI;
keep real seeds outside Git and reports. The module's `exercise()` shows the complete
API flow using a fresh ephemeral key rather than a committed seed.

The strict version-1 claim has purpose, scope/account/region, audience/key ID,
`export_sha256`, `expectations_sha256`, `captured_at`, `expires_at` and canonical
`signature_b64`. The signature covers canonical fields with a dedicated domain
separator. It cannot be substituted from the history-approval purpose.

## Verify permitted retained files

Select independently reviewed originals, claim and public policy, independent
claim/policy byte pins and a trusted recipient verification instant:

```bash
python -m engine.discovery.ec2_collector_attestation verify \
  /private/export.json /private/roster.json /private/claim.json /private/policy.json \
  --expected-claim-sha256 INDEPENDENT_CLAIM_SHA256 \
  --expected-policy-sha256 INDEPENDENT_POLICY_SHA256 \
  --scope owned --account SELECTED_ACCOUNT --region SELECTED_REGION \
  --audience SELECTED_RECIPIENT --at TRUSTED_UTC_INSTANT \
  --output /private/reviews/new-attested-review.json
```

Placeholders are intentionally invalid. Whole-second UTC timestamps end in `Z`.
The trusted selected `at` must satisfy `captured_at <= at < expires_at`. The complete
capture/expiry interval must fit the key's window and policy maximum. `at` is a
recipient input and needs a trusted clock/process; it is not taken from the claim.
Active keys create/verify, retired keys verify, revoked keys reject. There is no
historical retirement cutoff, so retirement alone does not prove creation time.

Both independent pins precede parsing. Signature/context/window checks precede
original/roster parsing; their exact signed hashes precede network reproduction.
Claim/policy/export/roster/report limits are 4 KiB/64 KiB/4 MiB/256 KiB/16 MiB.
Existing bounded POSIX regular no-follow readers and exclusive private publication
are reused. Trust ancestor directories and cooperative writers; no locking,
encryption, hostile-file sandbox or crash-durability claim is added.

Exit 0 means verification and report creation completed, including roster mismatch.
Stdout includes status, signature flag, roster-match flag and digest, with source
verification explicitly false. Key IDs, capture claims and full network differences
stay in the new mode-0600 report. Inputs are unchanged; outputs are never overwritten.
Errors return 2 with a fixed diagnostic. Keep private reports outside Git.

## Boundaries and next work

`collector_signature_verified` concerns an enrolled key under the selected policy.
It does not prove physical collector identity, AWS origin, truthful capture time,
full collection, current attachment or exposure. `aws_source_verified` and
`collection_completeness_established` stay false; `capture_time_is_claim` stays true.
Repeated verification is allowed until expiry. There is no nonce store, one-time
action, latest-policy distribution or rollback-resistant selection.

Tests use real ephemeral Ed25519 signatures with socket creation blocked. They cover
substituted inputs, altered fields, wrong context/purpose/key, revoked/retired keys,
window edges, policy limits, pins before parsing and private read-only CLI handling.
Prepared with assistant support and synthetic inputs. Next: trusted current
policy/roster distribution and independent capture-process evidence before decisions.
