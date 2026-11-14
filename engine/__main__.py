"""Discover and run the bundled temporary exercises without optional imports at help time."""

import argparse
import importlib
import json
import sys


# Only these bundled exercises can run. User input never becomes a module path.
WORKFLOWS = (
    ("inventory", "demo_inventory", "standard-library", "Import, assess and reproduce saved osquery inventory"),
    ("assessment-backup", "demo_assessment_backup", "standard-library", "Restore an exact closed assessment backup"),
    ("assessment-archive", "demo_assessment_archive", "standard-library", "Restore an assessment with retained replay inputs"),
    ("ec2-compare", "demo_ec2_discovery_compare", "standard-library", "Compare two saved EC2 discovery batches"),
    ("ec2-timeline", "demo_ec2_timeline", "standard-library", "Review a sequence of saved EC2 observations"),
    ("ec2-checkpoint", "demo_ec2_checkpoint", "standard-library", "Check expected and supplied EC2 batches"),
    ("ec2-archive", "demo_ec2_archive", "standard-library", "Restore a saved EC2 sequence and its inputs"),
    ("ec2-review", "demo_ec2_review", "standard-library", "Compare independent EC2 review receipts"),
    ("ec2-history", "demo_ec2_history", "standard-library", "Reproduce ordered same-model EC2 reviews"),
    ("ec2-history-backup", "demo_ec2_history_backup", "standard-library", "Restore a closed EC2 review history"),
    ("ec2-history-archive", "demo_ec2_history_archive", "standard-library", "Restore EC2 history with replay inputs"),
    ("ec2-enrollment", "demo_ec2_enrollment", "standard-library", "Select and advance a reproduced history revision"),
    ("ec2-approval", "demo_ec2_approval", "requirements-review.txt", "Verify an enrolled key's history approval"),
    ("ec2-recipient", "demo_ec2_recipient", "requirements-review.txt", "Accept a signed selection under a local checkpoint"),
    ("ec2-operator", "demo_ec2_operator", "requirements-review.txt", "Require separately enrolled operator consent"),
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Zero Shadow local exercises. Python 3.11+ on POSIX. Bundled synthetic "
        "inputs, temporary files, no network or remediation actions. "
        "Retained-file commands: docs/local-workflows.md."))
    commands = parser.add_subparsers(dest="command", required=True)
    catalog = commands.add_parser("list", help="show exercises and dependency requirements")
    catalog.add_argument("--format", choices=("text", "json"), default="text")
    demo = commands.add_parser("demo", help="run one temporary synthetic exercise")
    demo.add_argument("workflow", choices=[item[0] for item in WORKFLOWS])
    args = parser.parse_args(argv)
    if args.command == "list":
        if args.format == "json":
            print(json.dumps({"schema_version": 1, "workflows": [
                dict(name=name, dependencies=dependencies, description=description)
                for name, _, dependencies, description in WORKFLOWS]}, sort_keys=True))
        else:
            print("Temporary synthetic exercises, Python 3.11+ on POSIX. No network calls.")
            for name, _, dependencies, description in WORKFLOWS:
                print(f"{name}: {description} [{dependencies}]")
            print("Run: python -m engine demo NAME")
            print("Retained files and limits: docs/local-workflows.md")
        return 0
    _, module, dependencies, _ = next(item for item in WORKFLOWS if item[0] == args.workflow)
    try:
        selected = importlib.import_module("engine." + module)
    except ImportError:
        print(f"error: exercise dependency unavailable; see {dependencies} and README.md", file=sys.stderr)
        return 2
    return selected.main()


if __name__ == "__main__":
    raise SystemExit(main())
