# Accept a selection with separately enrolled operator consent

A history authority can approve evidence without authorizing a recipient to replace
its accepted checkpoint. This opt-in command requires a second, purpose-separated
Ed25519 consent before calling the existing locked acceptance workflow. Prepared
with assistant support.

## Run the temporary exercise

On POSIX with Python 3.11 or newer, from the repository root:

```bash
python -m pip install -r requirements-review.txt
python -m engine.demo_ec2_operator
```

Expect `ec2_operator_exercise_passed`, `accepted_revision: 2`,
`operator_approval_verified: true`, two separate key roles and five rejected
negative cases. Native SQLite and Ed25519 use temporary synthetic evidence and
ephemeral in-memory keys. The exercise drops the private operator key reference
before verifying bootstrap and successor consent. Inputs stay unchanged and
network socket creation is blocked. No AWS or external identity service is used.
Dropping a Python reference does not establish secure memory erasure.

## Enroll the operator role deliberately

Create a separate privately retained authority policy with the same exact shape
as the [history approval policy](ec2-import.md#independent-history-approval), but
set its `purpose` to `zero-shadow-ec2-operator-acceptance-v1`. Its `audience` must
match this recipient. Enroll the public operator key and its validity/state through
a trusted process, then retain the exact policy digest independently. The demo's
`operator_policy` helper creates an illustrative synthetic policy, not a production
identity enrollment system. Keep private seeds outside Git in owned mode-0600 files.

The policy's separate purpose and signature domain prevent a history approval from
being used as operator consent. The example uses two different keys; the software
does not enforce that administrators enroll distinct humans or keys across policies.
Real role separation remains an enrollment decision.

## Sign one exact transition

Use an enrollment and history approval produced by the
[selection workflow](ec2-history-enrollment.md). Review the selected candidate pin,
previous accepted pin, recipient and history-authority policy pin deliberately.
Uppercase values below are independently retained lowercase SHA-256 placeholders:

```bash
python -m database.ec2_operator_acceptance sign \
  --enrollment /private/handoff/selection-2.json \
  --expected-enrollment-sha256 SELECTION_2_PIN \
  --expected-accepted-sha256 SELECTION_1_PIN \
  --expected-policy-sha256 HISTORY_AUTHORITY_POLICY_PIN \
  --operator-policy /private/trust/operators.json \
  --expected-operator-policy-sha256 OPERATOR_POLICY_PIN \
  --audience fixture-recipient --at 2026-10-28T01:00:00Z \
  --seed-file /private/keys/operator.seed --key-id fixture-operator \
  --issued-at 2026-10-28T01:00:00Z --expires-at 2026-10-28T02:00:00Z \
  --output /private/review/consent-2.json
```

The October timestamps are synthetic fixture instants. Use an actual trusted clock
and reviewed validity window for retained data. Bootstrap uses `--bootstrap` instead
of `--expected-accepted-sha256` and must name an initial enrollment. Signing validates
the selection and pins but does not reproduce the history or replace a checkpoint.
Consent binds the exact candidate and predecessor, both policy digests, recipient
and validity window. It is published to a fresh private file without overwriting.

## Verify consent and replace the checkpoint

The recipient does not need the operator's seed:

```bash
python -m database.ec2_operator_acceptance accept /private/recipient/accepted.json \
  /private/handoff/history-2.sqlite /private/handoff/history-approval-2.json \
  --operator-approval /private/review/consent-2.json \
  --enrollment /private/handoff/selection-2.json \
  --expected-enrollment-sha256 SELECTION_2_PIN \
  --expected-accepted-sha256 SELECTION_1_PIN \
  --export /private/handoff/export.json --policy /private/trust/history-authority.json \
  --expected-policy-sha256 HISTORY_AUTHORITY_POLICY_PIN \
  --operator-policy /private/trust/operators.json \
  --expected-operator-policy-sha256 OPERATOR_POLICY_PIN \
  --audience fixture-recipient --at 2026-10-28T01:00:00Z
```

Success returns `ec2_operator_acceptance_completed` and `operator_approval_verified`.
Consent is checked before checkpoint access. The existing acceptance function then
checks the selected predecessor under its persistent writer lock, verifies the
history authority signature and complete evidence lineage, and publishes the exact
candidate bytes. Wrong/missing consent, changed pins or recipient, expired consent,
changed evidence, stale state and invalid history approval cannot complete acceptance.
A changed operator policy digest requires newly reviewed consent, even with the same
public key. Keep consent and policy bytes for later review; they are not an audit log.

## Boundaries

This command is opt-in. The original local acceptance API/CLI remains available and
does not require operator consent. A recipient that requires this check must choose
and control this command in its own workflow. Nothing prevents the same local user
from bypassing advisory locks or rewriting files. No global enforcement flag or
operator identity directory is added.

Verification authenticates an enrolled key's statement at the supplied clock. It
does not prove a human reviewed the material, enroll that human, discover a newer
policy or selection, or prevent rollback of both state and separately trusted pins.
Copies of a checkpoint share its lineage; consent is not globally single-use.
The existing [lock and interrupted-response recovery limits](ec2-recipient-checkpoint.md#lock-failure-and-trust-boundaries)
still apply. No cloud action, remediation approval or global latest-head claim follows.

Next: retain independently verifiable acceptance/recovery evidence and define trusted
operator enrollment before coupling local acceptance to action authorization.
