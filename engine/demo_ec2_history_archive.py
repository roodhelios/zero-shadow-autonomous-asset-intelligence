"""Restore a synthetic EC2 review history after deleting its history and original export."""

import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from database.ec2_history_archive import create_archive, restore_archive, verify_archive
from database.ec2_review_history import verify_history
from engine.demo_ec2_history_backup import prepare_history


def exercise():
    with tempfile.TemporaryDirectory(prefix='ec2-history-archive-') as directory:
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            root = Path(directory)
            history, export, head = prepare_history(root)
            original = history.read_bytes()
            source = root/'original-export.json'
            source.write_bytes(export)
            archive = root/'archive.json'
            saved = create_archive(history, archive, export_data=source.read_bytes(), expected_head=head)
            before = archive.read_bytes()
            history.unlink()
            source.unlink()
            options = dict(expected_sha256=saved['archive_sha256'], expected_head=head)
            verify_archive(archive, **options)
            restored = root/'restored'
            result = restore_archive(archive, restored, **options)
            if ((restored/'history.sqlite').read_bytes() != original or
                    (restored/'export.json').read_bytes() != export or archive.read_bytes() != before):
                raise ValueError('exact retained bytes did not restore')
            verify_history(restored/'history.sqlite', export_data=(restored/'export.json').read_bytes(),
                           expected_head=head)
            rejected = 0
            for overrides in ({'expected_sha256': '0'*64}, {'expected_head': '0'*64}):
                try:
                    restore_archive(archive, root/'refused', **(options | overrides))
                except ValueError:
                    if (root/'refused').exists():
                        raise ValueError('rejected restore published output')
                    rejected += 1
                else:
                    raise ValueError('changed independent pin accepted')
            try:
                restore_archive(archive, restored, **options)
            except FileExistsError:
                rejected += 1
            else:
                raise ValueError('existing restored directory was reused')
    return dict(status='ec2_history_archive_exercise_passed', review_count=result['review_count'],
                decision_count=result['decision_count'], original_history_removed=True,
                original_export_removed=True, exact_bytes_restored=True,
                negative_cases_rejected=rejected)


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError):
        print('error: EC2 history archive exercise failed', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
