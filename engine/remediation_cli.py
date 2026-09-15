"""JSON Lines command for fixture-backed remediation planning."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import ExitStack
from datetime import date
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from .remediation import plan_remediation
from .risk import FindingEvidence, FindingValidationError, score_finding


class RemediationInputError(ValueError):
    """Raised when a planning record cannot be interpreted safely."""


def _date(value: Any, field_name: str) -> date:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must use YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DD") from exc


def _plan_record(record: Mapping[str, Any], *, as_of: date) -> dict[str, Any]:
    finding = record.get("finding")
    if not isinstance(finding, Mapping):
        raise ValueError("finding must be an object")
    requested_due = record.get("requested_due_date")
    return plan_remediation(
        score_finding(FindingEvidence.from_dict(finding)),
        owner=record.get("owner"),
        opened_on=_date(record.get("opened_on"), "opened_on"),
        as_of=as_of,
        requested_due_date=(
            _date(requested_due, "requested_due_date")
            if requested_due is not None
            else None
        ),
    ).to_dict()


def plan_jsonl(
    source: TextIO,
    destination: TextIO,
    *,
    as_of: date,
    source_name: str = "<stdin>",
) -> int:
    """Plan non-empty JSON Lines records and return the emitted count."""

    emitted = 0
    for line_number, line in enumerate(source, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, Mapping):
                raise ValueError("record must be an object")
            output = _plan_record(record, as_of=as_of)
        except json.JSONDecodeError as exc:
            raise RemediationInputError(
                f"{source_name}:{line_number}: invalid JSON ({exc.msg})"
            ) from exc
        except (FindingValidationError, ValueError) as exc:
            raise RemediationInputError(f"{source_name}:{line_number}: {exc}") from exc

        destination.write(json.dumps(output, sort_keys=True, separators=(",", ":")))
        destination.write("\n")
        emitted += 1
    return emitted


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create explainable remediation plans from local JSON Lines"
    )
    parser.add_argument("input", nargs="?", default="-")
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--output", "-o", default="-")
    args = parser.parse_args(argv)

    try:
        as_of = _date(args.as_of, "as_of")
        with ExitStack() as stack:
            source = (
                sys.stdin
                if args.input == "-"
                else stack.enter_context(Path(args.input).open(encoding="utf-8"))
            )
            destination = (
                sys.stdout
                if args.output == "-"
                else stack.enter_context(
                    Path(args.output).open("w", encoding="utf-8", newline="\n")
                )
            )
            plan_jsonl(source, destination, as_of=as_of, source_name=args.input)
    except (OSError, RemediationInputError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
