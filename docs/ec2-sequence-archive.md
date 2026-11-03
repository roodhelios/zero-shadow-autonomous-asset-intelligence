# Retain an EC2 sequence and its replay inputs together

The sequence checkpoint report previously needed several separate databases,
original exports and recipient expectations to reproduce. Losing one original
could make a retained report unusable. This archive captures the supplied closed
databases, original export bytes, exact checkpoint, reproduced coverage report and
an allowlisted source snapshot in one private JSON file.

It is a local retention workflow. It does not contact AWS, collect evidence,
authenticate a source or establish that a checkpoint is current. A partial sequence
can be archived honestly. Its missing batches remain missing after restoration.

## Try the complete temporary exercise

From the repository root on POSIX with Python 3.11 or newer:

```bash
python -S -m engine.demo_ec2_archive
```

Expect `ec2_sequence_archive_exercise_passed`, two supplied batches, three expected
batches, one missing batch, `originals_removed: true`, `exact_bytes_restored: true`
and three rejected negative cases. The restored report reproduces against its
restored databases and original exports. The command uses native temporary SQLite,
original synthetic exports and the standard library. It removes temporary files
and forbids Python socket creation. No credential, account, model or service is used.

## Create a retained archive

First retain the [saved EC2 imports](ec2-import.md) and an independently controlled
[recipient sequence checkpoint](ec2-sequence-checkpoint.md). Close writers and
checkpoint SQLite before retention. Use trusted private paths outside Git.

```bash
umask 077
mkdir -m 700 /private/ec2-retention
python -S -m database.ec2_sequence_archive create \
  --batch /private/ec2/first.sqlite /private/ec2/first-export.json \
  --batch /private/ec2/later.sqlite /private/ec2/later-export.json \
  --checkpoint /private/recipient/checkpoint.json \
  --expected-checkpoint-sha256 TRUSTED_CHECKPOINT_SHA256 \
  --output /private/ec2-retention/sequence.archive.json
```

Paths and uppercase digests are placeholders. The output parent must already be
an owned 0700 directory. Input databases must be owned, single-link regular 0600
files in owned 0700 parents, without WAL, SHM or journal sidecars. Symlinks fail.
Existing archive paths are never replaced. Each captured database is reproduced
against its corresponding exact original export before publication. Only captured
copies feed replay; mutable source files are not reread for that decision.

Retain the printed `archive_sha256` separately from the archive. Keep the recipient
checkpoint pin independently controlled as well. A digest calculated only from an
untrusted received archive cannot establish trust in that archive or its expectations.

Exit 0 means supplied evidence satisfies the pinned checkpoint. Exit 1 means a
valid retained archive has checkpoint gaps. Exit 2 means failure. A successfully
stored partial archive is evidence retention, not collection success. Output
summaries omit database paths and raw asset claims but still contain sensitive
digests and operational counts. Keep them private.

## Verify and restore after the originals are unavailable

```bash
python -S -m database.ec2_sequence_archive verify \
  /private/ec2-retention/sequence.archive.json \
  --expected-sha256 TRUSTED_ARCHIVE_SHA256 \
  --expected-checkpoint-sha256 TRUSTED_CHECKPOINT_SHA256

python -S -m database.ec2_sequence_archive restore \
  /private/ec2-retention/sequence.archive.json \
  --expected-sha256 TRUSTED_ARCHIVE_SHA256 \
  --expected-checkpoint-sha256 TRUSTED_CHECKPOINT_SHA256 \
  --output /private/ec2-retention/restored-sequence
```

Verification requires a matching trusted current checkout. Archived code is compared
as bytes and never imported or executed. Complete coverage must reproduce from the
archived databases, exports and separately pinned checkpoint. Verification runs in
temporary private SQLite files and does not modify the archive or original inputs.

Restore requires a new directory whose private parent already exists. An existing
directory, including an empty one, is preserved. Fixed filenames retain the supplied
order: `01.sqlite`, `01.json`, `02.sqlite`, `02.json` and so on. These contain exact
database and original export bytes. `checkpoint.json` and `coverage.json` retain
their exact bytes. `RESTORE.json` is written last as a completion receipt. Restored
files use 0600 and the directory uses 0700. No archived source is extracted.

For two restored batches, independently reproduce coverage with the existing tool:

```bash
python -S -m database.ec2_timeline_checkpoint verify \
  /private/ec2-retention/restored-sequence/coverage.json \
  --batch /private/ec2-retention/restored-sequence/01.sqlite /private/ec2-retention/restored-sequence/01.json \
  --batch /private/ec2-retention/restored-sequence/02.sqlite /private/ec2-retention/restored-sequence/02.json \
  --checkpoint /private/ec2-retention/restored-sequence/checkpoint.json \
  --expected-checkpoint-sha256 TRUSTED_CHECKPOINT_SHA256 \
  --expected-report-sha256 TRUSTED_COVERAGE_SHA256
```

Use the independently retained coverage pin from report creation or compute it from
coverage that has just passed archive verification. That computation alone does not
authenticate a separately received coverage file.

## Bounds and remaining work

Two to sixteen batches are supported. Each database is at most 16 MiB and each
export at most 4 MiB. Combined captured database/export bytes are at most 16 MiB;
the archive is at most 32 MiB, checkpoint/coverage at most 64 KiB each, and the
allowlisted source snapshot at most 1 MiB. Base64 is retention encoding, not encryption.
Detailed source claims can contain private data. Never commit real archives.

The archive file uses same-directory staging and no-replace publication. Multi-file
restore uses an exclusive directory and completion-last receipt, not atomic directory
publication. Caught failures remove only the new incomplete restore; process death
can leave an incomplete directory. Never treat its existence as completion. File
fsync does not guarantee parent-directory power-loss durability. Trusted ancestors,
a cooperative single host and closed writers remain required. Captures of separate
databases are not one atomic account snapshot.

This supports EC2 discovery sequence coverage, not EC2 assessment histories, active
database backup, historical implementation dispatch, source authentication or fresh
global checkpoint distribution. A stale archive can still match its own stale pins.
Independent enrollment, freshness and current authority remain recipient decisions.

Next: design independently controlled checkpoint enrollment and freshness before
connecting an authorized collection source. Implemented with assistant support and
native local synthetic validation.
