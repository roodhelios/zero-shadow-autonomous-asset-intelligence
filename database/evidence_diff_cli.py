"""Compare two local asset evidence snapshot files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .evidence_diff import EvidenceDiffError, compare_snapshots, load_snapshot


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two verified local asset evidence snapshots"
    )
    parser.add_argument("base", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        for path, field_name in ((args.base, "base"), (args.current, "current")):
            if "://" in str(path):
                raise EvidenceDiffError(f"{field_name} must be a local path")
        base = args.base.resolve(strict=True)
        current = args.current.resolve(strict=True)
        if base == current:
            raise EvidenceDiffError("base and current snapshots must differ")
        if args.output:
            output = args.output.resolve()
            if output in {base, current}:
                raise EvidenceDiffError("output must differ from both snapshots")
            if output.exists():
                raise EvidenceDiffError("output already exists")
        result = compare_snapshots(load_snapshot(base), load_snapshot(current))
        rendered = json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (EvidenceDiffError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
