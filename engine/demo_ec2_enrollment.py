"""Exercise pinned EC2 history selection and lineage advance with temporary synthetic data."""

from datetime import date, datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from database.ec2_assessment import retain_assessment
from database.ec2_history_backup import backup_history
from database.ec2_history_enrollment import enroll_history, advance_enrollment, verify_enrollment, _digest
from database.ec2_inventory import store_ec2
from database.ec2_review_history import retain_history


def prepare_histories(work):
    examples = Path(__file__).resolve().parents[1]/'examples'
    export = (examples/'ec2-describe-instances.json').read_bytes()
    finding = json.loads((examples/'ec2-findings.jsonl').read_bytes())
    directory = (examples/'ownership-directory.json').read_bytes()
    source, discovery = work/'export.json', work/'discovery.sqlite'
    source.write_bytes(export)
    store_ec2(source, discovery, scope='synthetic', account='111122223333', region='us-east-1',
              observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
    histories, heads, receipts = [], [], []
    for index, severity in enumerate(('high', 'critical', 'medium')):
        finding['finding']['severity'] = severity
        day = date(2026, 10, 25+index)
        receipt, history = work/f'review-{index}.sqlite', work/f'history-{index}.sqlite'
        retain_assessment(discovery, json.dumps(finding).encode(), directory, receipt, export_data=export,
                          as_of=day, assessed_at=datetime(day.year, day.month, day.day, 1, tzinfo=timezone.utc))
        saved = retain_history(receipt, history, export_data=export,
            history=histories[-1] if histories else None, expected_head=heads[-1] if heads else None)
        histories.append(history); heads.append(saved['head_sha256']); receipts.append(receipt)
    return histories, heads, receipts, export


def exercise():
    with tempfile.TemporaryDirectory(prefix='ec2-history-enrollment-') as directory:
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            root = Path(directory)
            histories, heads, _, export = prepare_histories(root)
            initial, advanced = root/'enrollment-1.json', root/'enrollment-2.json'
            enroll_history(histories[0], initial, export_data=export, expected_head=heads[0])
            first = initial.read_bytes()
            advance_enrollment(histories[1], advanced, enrollment_data=first,
                expected_enrollment_sha256=_digest(first), export_data=export, expected_head=heads[1])
            second = advanced.read_bytes()
            copy = root/'restored-history.sqlite'
            backup_history(histories[1], copy, export_data=export, expected_head=heads[1])
            original = histories[1].read_bytes()
            histories[1].unlink()
            checked = verify_enrollment(copy, enrollment_data=second,
                expected_enrollment_sha256=_digest(second), export_data=export)
            rejected = 0
            operations = (
                lambda: verify_enrollment(histories[0], enrollment_data=second,
                    expected_enrollment_sha256=_digest(second), export_data=export),
                lambda: verify_enrollment(copy, enrollment_data=second,
                    expected_enrollment_sha256='0'*64, export_data=export),
                lambda: verify_enrollment(copy, enrollment_data=second,
                    expected_enrollment_sha256=_digest(second), export_data=export+b'\n'),
                lambda: advance_enrollment(copy, root/'refused.json', enrollment_data=second,
                    expected_enrollment_sha256=_digest(second), export_data=export, expected_head=heads[1]))
            for operation in operations:
                try: operation()
                except ValueError: rejected += 1
                else: raise ValueError('invalid selection accepted')
            # A separately selected old record still verifies its own old artifact.
            verify_enrollment(histories[0], enrollment_data=first,
                              expected_enrollment_sha256=_digest(first), export_data=export)
            if initial.read_bytes() != first or advanced.read_bytes() != second or copy.read_bytes() != original:
                raise ValueError('retained selection or history changed')
    return dict(status='ec2_history_enrollment_exercise_passed', revision=checked['revision'],
                review_count=checked['review_count'], negative_cases_rejected=rejected,
                original_history_removed=True, exact_copy_verified=True, old_selection_still_verifies=True,
                latest_head_established=False)


def main():
    try: result = exercise()
    except (OSError, ValueError, TypeError, KeyError):
        print('error: EC2 history enrollment exercise failed; inspect private fixtures and model', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
