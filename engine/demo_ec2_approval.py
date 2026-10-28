"""Exercise independent history approval using temporary original synthetic fixtures."""

import base64
import hashlib
import json
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

from database.ec2_assessment import retain_assessment
from database.ec2_history_approval import PURPOSE, approve_history, verify_approval
from database.ec2_inventory import store_ec2
from database.ec2_review_history import retain_history


def exercise():
    from nacl.signing import SigningKey
    root = Path(__file__).resolve().parents[1]
    export = (root/'examples/ec2-describe-instances.json').read_bytes()
    findings = (root/'examples/ec2-findings.jsonl').read_bytes()
    directory = (root/'examples/ownership-directory.json').read_bytes()
    with tempfile.TemporaryDirectory(prefix='zero-shadow-ec2-approval-') as name:
        work = Path(name); source = work/'export.json'; discovery = work/'discovery.sqlite'
        source.write_bytes(export); source.chmod(0o600)
        store_ec2(source, discovery, scope='synthetic', account='111122223333', region='us-east-1',
                  observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        receipt, history = work/'receipt.sqlite', work/'history.sqlite'
        retain_assessment(discovery, findings, directory, receipt, export_data=export,
                          as_of=date(2026, 10, 25), assessed_at=datetime(2026, 10, 25, 1, tzinfo=timezone.utc))
        retain_history(receipt, history, export_data=export)
        discovery.unlink()
        signer = SigningKey.generate()
        policy = {"schema_version": 1, "purpose": PURPOSE, "audience": "fixture-recipient",
                  "max_validity_seconds": 3600, "keys": [{"key_id": "fixture-reviewer",
                  "public_key_b64": base64.b64encode(signer.verify_key.encode()).decode('ascii'),
                  "state": "active", "not_before": "2026-10-28T00:00:00Z", "not_after": "2026-10-29T00:00:00Z"}]}
        policy_data = json.dumps(policy).encode()
        shared = dict(export_data=export, policy_data=policy_data,
                      expected_policy_sha256=hashlib.sha256(policy_data).hexdigest(),
                      audience='fixture-recipient', at='2026-10-28T01:00:00Z')
        saved = {p: p.read_bytes() for p in (source, receipt, history)}
        approval = approve_history(history, **shared, seed=signer.encode(), key_id='fixture-reviewer',
                                   issued_at='2026-10-28T01:00:00Z', expires_at='2026-10-28T02:00:00Z')
        del signer
        encoded = json.dumps(approval).encode()
        result = verify_approval(history, encoded, **shared)
        for change in ({'export_data': export+b'\n'}, {'expected_policy_sha256': '0'*64},
                       {'audience': 'other-recipient'}, {'at': '2026-10-28T02:00:00Z'}):
            try:
                verify_approval(history, encoded, **dict(shared, **change))
            except ValueError:
                pass
            else:
                raise ValueError('invalid approval context accepted')
        if any(p.read_bytes() != data for p, data in saved.items()):
            raise ValueError('input evidence changed')
    return dict(result, status='ec2_approval_exercise_passed', inputs_unchanged=True,
                negative_cases_rejected=4, private_signer_removed_before_verify=True)


def main():
    try:
        result = exercise()
    except (ImportError, OSError, ValueError, TypeError, KeyError):
        print('error: local EC2 approval exercise failed; install requirements-review.txt and inspect fixtures privately',
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
