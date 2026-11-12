"""Accept a signed EC2 selection into a recipient-controlled local checkpoint."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile

from database.assessment_backup import _private_directory
from database.ec2_history_approval import _file, verify_approval
from database.ec2_history_enrollment import _parse, read_enrollment
from database.ec2_review_history import _check_digest
from engine.discovery.osquery_collector import _read


@contextmanager
def _writer_lock(checkpoint):
    # Keep this inode permanently. Unlinking a lock lets writers lock different files.
    import fcntl
    lock = checkpoint.parent / ('.' + checkpoint.name + '.lock')
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != 0):
            raise ValueError('expected owned private single-link lock file')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def _commit(checkpoint, data, bootstrap):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=checkpoint.parent,
                                         prefix='.ec2-checkpoint-', delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if bootstrap:
            os.link(temporary, checkpoint)
        else:
            os.replace(temporary, checkpoint)
        temporary.unlink(missing_ok=True)
        descriptor = os.open(checkpoint.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def accept_checkpoint(checkpoint, history, approval_data, *, enrollment_data,
                      expected_enrollment_sha256, export_data, policy_data,
                      expected_policy_sha256, audience, at,
                      expected_accepted_sha256=None, bootstrap=False):
    """Verify and replace under one advisory lock, with an explicit predecessor pin."""
    if os.name != 'posix':
        raise ValueError('recipient checkpoints require POSIX file locks')
    if type(bootstrap) is not bool or bootstrap == (expected_accepted_sha256 is not None):
        raise ValueError('choose bootstrap or an expected accepted checkpoint digest')
    if not bootstrap:
        _check_digest(expected_accepted_sha256)
    candidate = _parse(enrollment_data, expected_enrollment_sha256)
    checkpoint = Path(checkpoint)
    _private_directory(checkpoint.parent)
    with _writer_lock(checkpoint):
        previous = {}
        if bootstrap:
            if candidate['revision'] != 1 or os.path.lexists(checkpoint):
                raise ValueError('bootstrap requires a new path and an initial selection')
        else:
            accepted = read_enrollment(checkpoint)
            _parse(accepted, expected_accepted_sha256)
            previous = dict(previous_enrollment_data=accepted,
                            expected_previous_sha256=expected_accepted_sha256)
        result = verify_approval(history, approval_data, export_data=export_data,
            policy_data=policy_data, expected_policy_sha256=expected_policy_sha256,
            audience=audience, at=at, enrollment_data=enrollment_data,
            expected_enrollment_sha256=expected_enrollment_sha256, **previous)
        _commit(checkpoint, enrollment_data, bootstrap)
    return dict(result, status='ec2_recipient_checkpoint_accepted',
        checkpoint_sha256=expected_enrollment_sha256, bootstrapped=bootstrap,
        interpretation='Recipient-local acceptance under an advisory writer lock. Trusted storage, '
        'policy, clock and pins remain required; this does not establish global freshness.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('checkpoint', type=Path)
    parser.add_argument('history', type=Path)
    parser.add_argument('approval', type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--bootstrap', action='store_true')
    mode.add_argument('--expected-accepted-sha256')
    parser.add_argument('--enrollment', type=Path, required=True)
    parser.add_argument('--expected-enrollment-sha256', required=True)
    parser.add_argument('--export', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--expected-policy-sha256', required=True)
    parser.add_argument('--audience', required=True)
    parser.add_argument('--at', required=True)
    args = parser.parse_args(argv)
    try:
        result = accept_checkpoint(args.checkpoint, args.history, _file(args.approval, 4096),
            enrollment_data=read_enrollment(args.enrollment),
            expected_enrollment_sha256=args.expected_enrollment_sha256,
            export_data=_read(args.export), policy_data=_file(args.policy, 64 * 1024),
            expected_policy_sha256=args.expected_policy_sha256, audience=args.audience, at=args.at,
            bootstrap=args.bootstrap, expected_accepted_sha256=args.expected_accepted_sha256)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError, UnicodeError,
            RecursionError, OverflowError):
        print('error: checkpoint acceptance did not confirm success; inspect private state and pins before retrying',
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
