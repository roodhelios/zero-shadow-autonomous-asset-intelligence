# Import a saved EC2 export

From the repository root on POSIX with Python 3.11 or newer:

```bash
python -m engine.discovery.aws_discovery examples/ec2-describe-instances.json \
  --scope synthetic --account 111122223333 --region us-east-1 --format inventory
```

Expect one observation and one asset. The selected source identity is
`arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0`. Addresses are
documentation-only ranges. Supplied tags route reviewed work; they do not prove
accepted ownership. A public-address field is not an effective-exposure assessment.

The input is a saved JSON object in the AWS
[describe-instances output format](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html).
The importer reads `Reservations`, checks each `OwnerId` against the explicit
account, and projects each instance's ID, primary private/public IPv4 fields and
only the exact tag keys `environment`, `owner_group` and `service`. It preserves
the original byte digest and one-based reservation/instance references. DNS names,
instance state, other addresses and unselected metadata are not copied or inferred.
The fixture intentionally says `stopped`; inclusion never means running or reachable.

Without `--format inventory`, the output uses the existing fixture contract and can
feed the evidence workflow. A native SQLite regression test runs that complete path
with sockets blocked. `--output /private/new-ec2-fixture.json` publishes mode 0600
without replacing an existing file. Validate the full input before publishing.

The reader limits input to 4 MiB and 10,000 instances. It rejects duplicate JSON
fields, non-finite values, duplicate instance IDs, ambiguous tags, account mismatches
and nonempty pagination tokens. An export without a token can still be filtered or
incomplete. Empty reservations mean zero supplied observations, not zero real assets.

Only the commercial `aws` partition and the declared region-name subset are supported.
Region is caller supplied because it is not established by this projection. Incorrect
region claims produce incorrect identity context. China and GovCloud names fail.
Other sources must use the same full ARN to correlate by cloud identity; unqualified
instance IDs are deliberately different. Shared IP addresses never merge assets.

This command sends no AWS requests, needs no cloud credentials and creates no cloud
resources. Scope, source claims and account/region labels are not authenticated.
Live discovery, retained multi-source import receipts and region attestation remain
unfinished. Keep real exports private and outside Git. Assistant support was used
to implement and review this extension.
