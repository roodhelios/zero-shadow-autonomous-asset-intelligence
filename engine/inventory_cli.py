"""Retain and reproduce saved osquery or S3 inventory through local tools."""

import argparse
from importlib import import_module
import sys


# Fixed modules only. Arguments remain subject to each tool's existing validation.
COMMANDS = {
    "import": ("database.inventory_cli", "store a saved export in a new discovery database"),
    "export": ("database.inventory_export_cli", "inspect retained inventory and source coverage"),
    "assess": ("database.inventory_assessment_cli", "retain supplied findings and ownership decisions"),
    "verify": ("database.inventory_assessment_verify", "reproduce an assessment against its original export"),
    "queue": ("database.inventory_assessment_queue", "export a pinned assessment's dated work queue"),
    "verify-queue": ("database.inventory_assessment_queue_verify", "reproduce a queue using independent pins and date"),
}


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Commands:\n" + "\n".join(f"  {name:14} {description}"
            for name, (_, description) in COMMANDS.items()) +
            "\n\nUse COMMAND --help for paths, scope, pins and date requirements.")
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("arguments", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    if not arguments:
        parser.print_help()
        return 0
    selected = parser.parse_args(arguments)
    return import_module(COMMANDS[selected.command][0]).main(selected.arguments)


if __name__ == "__main__":
    raise SystemExit(main())
