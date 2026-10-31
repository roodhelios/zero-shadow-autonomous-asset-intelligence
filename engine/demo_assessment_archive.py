"""Restore a synthetic archive after removing the original assessment and export."""

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from datetime import date, datetime, timezone

from database.assessment_archive import create_archive, restore_archive, verify_archive
from database.inventory_assessment_cli import retain_assessment
from database.inventory_cli import store_export

EXAMPLES = Path(__file__).resolve().parents[1]/'examples'


def exercise():
    with tempfile.TemporaryDirectory(prefix='assessment-archive-demo-') as name:
        root = Path(name)
        for folder in ('original', 'archives', 'restored'): (root/folder).mkdir(mode=0o700)
        export = root/'original/export.json'
        export.write_bytes((EXAMPLES/'osquery-system-info-expanded.json').read_bytes()); export.chmod(0o600)
        discovery = root/'original/discovery.sqlite'; original = root/'original/assessment.sqlite'
        store_export(export, discovery, scope='synthetic', observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        retain_assessment(discovery, (EXAMPLES/'inventory-findings.jsonl').read_bytes(),
            (EXAMPLES/'ownership-directory.json').read_bytes(), original, as_of=date(2026, 10, 23),
            assessed_at=datetime(2026, 10, 23, 1, tzinfo=timezone.utc), export_data=export.read_bytes())
        before = original.read_bytes(); archive = root/'archives/assessment.json'
        created = create_archive(original, archive, export_data=export.read_bytes())
        pin = created['archive_sha256']; saved = archive.read_bytes()
        original.unlink(); discovery.unlink(); export.unlink()
        verified = verify_archive(archive, expected_sha256=pin)
        restored = root/'restored/assessment.sqlite'
        receipt = restore_archive(archive, restored, expected_sha256=pin)
        if restored.read_bytes() != before or archive.read_bytes() != saved:
            raise ValueError('archive restore changed checked bytes')
        rejected = 0
        for bad_pin in ('0'*64, 'not-a-digest'):
            try: restore_archive(archive, root/'restored/rejected.sqlite', expected_sha256=bad_pin)
            except ValueError: rejected += 1
            else: raise ValueError('invalid pin accepted')
        if (root/'restored/rejected.sqlite').exists(): raise ValueError('failed restore published output')
    return {'status': 'assessment_archive_exercise_passed', 'asset_count': receipt['asset_count'],
        'finding_count': receipt['finding_count'], 'model_status': receipt['model_status'],
        'original_database_and_export_removed': True, 'exact_database_bytes_restored': True,
        'archive_unchanged': True, 'negative_cases_rejected': rejected,
        'source_files': verified['source_files'], 'archived_code_executed': False,
        'interpretation': 'Temporary native SQLite and fixed synthetic dates. Matching trusted checkout required. '
        'No encryption, source authentication, remote backup, historical dispatch or power-loss validation.'}


def main():
    try: result = exercise()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: local assessment archive exercise failed', file=sys.stderr); return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__': raise SystemExit(main())
