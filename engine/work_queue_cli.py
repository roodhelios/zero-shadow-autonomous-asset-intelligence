"""Build local remediation work queues from fixture findings and ownership rules."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, Mapping, Sequence

from .ownership import OwnershipError, load_directory
from .remediation import plan_remediation
from .risk import FindingEvidence, FindingValidationError, score_finding
from .work_queue import QueueItem, build_work_queue_document


class WorkQueueInputError(ValueError):
    """Raised when a fixture record cannot be queued safely."""


def _date(value: Any, field_name: str) -> date:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must use YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DD") from exc


def build_from_jsonl(
    source_path: str | Path,
    *,
    directory_path: str | Path,
    as_of: date,
) -> dict[str, Any]:
    """Read local JSON Lines and return a deterministic queue document."""

    directory = load_directory(directory_path)
    source = Path(source_path)
    items: list[QueueItem] = []
    with source.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, Mapping):
                    raise ValueError("record must be an object")
                finding = record.get("finding")
                if not isinstance(finding, Mapping):
                    raise ValueError("finding must be an object")
                tags = record.get("asset_tags", {})
                resolution = directory.resolve(tags)
                requested_due = record.get("requested_due_date")
                plan = plan_remediation(
                    score_finding(FindingEvidence.from_dict(finding)),
                    owner=resolution.team_id,
                    opened_on=_date(record.get("opened_on"), "opened_on"),
                    as_of=as_of,
                    requested_due_date=(
                        _date(requested_due, "requested_due_date")
                        if requested_due is not None
                        else None
                    ),
                )
                items.append(QueueItem(plan=plan, ownership=resolution))
            except json.JSONDecodeError as exc:
                raise WorkQueueInputError(
                    f"{source}:{line_number}: invalid JSON ({exc.msg})"
                ) from exc
            except (FindingValidationError, OwnershipError, ValueError) as exc:
                raise WorkQueueInputError(f"{source}:{line_number}: {exc}") from exc

    return build_work_queue_document(items, directory=directory, as_of=as_of)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build fixture-backed remediation queues without sending tickets"
    )
    parser.add_argument("input")
    parser.add_argument("--directory", required=True)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--output", "-o", default="-")
    args = parser.parse_args(argv)

    try:
        document = build_from_jsonl(
            args.input,
            directory_path=args.directory,
            as_of=_date(args.as_of, "as_of"),
        )
        rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
        if args.output == "-":
            sys.stdout.write(rendered)
        else:
            Path(args.output).write_text(rendered, encoding="utf-8")
    except (OSError, OwnershipError, WorkQueueInputError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
