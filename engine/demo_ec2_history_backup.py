"""Restore both revisions after deleting the original synthetic EC2 review history."""

from datetime import date, datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from database.ec2_assessment import retain_assessment
from database.ec2_history_backup import backup_history, restore_history
from database.ec2_inventory import store_ec2
from database.ec2_review_history import retain_history


def prepare_history(work):
    """Create original temporary fixture evidence, not a live cloud assessment."""
    examples = Path(__file__).resolve().parents[1]/'examples'
    export = (examples/'ec2-describe-instances.json').read_bytes()
    findings = (examples/'ec2-findings.jsonl').read_bytes()
    directory = (examples/'ownership-directory.json').read_bytes()
    source, discovery = work/'export.json', work/'discovery.sqlite'
    source.write_bytes(export)
    store_ec2(source, discovery, scope='synthetic', account='111122223333', region='us-east-1',
              observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
    changed = json.loads(findings); changed['finding']['severity'] = 'critical'
    previous, head = None, None
    for index, data in enumerate((findings, json.dumps(changed).encode())):
        day = date(2026, 10, 25 + index)
        receipt, history = work/f'review-{index}.sqlite', work/f'history-{index}.sqlite'
        retain_assessment(discovery, data, directory, receipt, export_data=export, as_of=day,
                          assessed_at=datetime(day.year, day.month, day.day, 1, tzinfo=timezone.utc))
        result = retain_history(receipt, history, export_data=export, history=previous, expected_head=head)
        previous, head = history, result['head_sha256']
        receipt.unlink()
    discovery.unlink(); source.unlink(); (work/'history-0.sqlite').unlink()
    return previous, export, head


def exercise():
    with tempfile.TemporaryDirectory(prefix='ec2-history-backup-') as directory:
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            root = Path(directory)
            history, export, head = prepare_history(root)
            original = history.read_bytes()
            backup = root/'backup.sqlite'
            saved = backup_history(history, backup, export_data=export, expected_head=head)
            history.unlink()
            options = dict(export_data=export, expected_head=head, expected_sha256=saved['database_sha256'])
            result = restore_history(backup, root/'restored.sqlite', **options)
            if (root/'restored.sqlite').read_bytes() != original or backup.read_bytes() != original:
                raise ValueError('exact history bytes were not preserved')
            rejected = 0
            for overrides in ({'expected_head': '0'*64}, {'expected_sha256': '0'*64},
                              {'export_data': export+b'\n'}):
                output = root/'refused.sqlite'
                try: restore_history(backup, output, **(options | overrides))
                except ValueError:
                    if output.exists(): raise ValueError('failed restore published output')
                    rejected += 1
                else: raise ValueError('changed evidence or pin accepted')
    return dict(status='ec2_history_backup_exercise_passed', review_count=result['review_count'],
                decision_count=result['decision_count'], original_history_removed=True,
                exact_bytes_restored=True, negative_cases_rejected=rejected)


def main():
    try: result = exercise()
    except (OSError, ValueError, TypeError, KeyError):
        print('error: EC2 history backup exercise failed', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
