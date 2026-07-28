"""AUL Parser — command-line entry point.

This module is a thin **dispatcher**: it builds the argument parser by asking each
subcommand module in ``launcher/cmds/`` to register itself, then routes the parsed
arguments to that module's ``run(args)``. All command logic lives in the
``launcher/cmds/*_cmd.py`` handlers — nothing command-specific belongs here.

Global options
--------------
--verbose / -v      Enable DEBUG-level logging on the console (file always INFO).

With no subcommand, the GUI is launched.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import sys

from forensic_aul import __version__

log = logging.getLogger(__name__)

# Each subcommand module exposes add_subcommand(sub) + run(args). Registration
# order is the order they appear in --help.
# Registration order = workflow order, which is also the order --help prints.
_COMMAND_MODULES = (
    "acquire_cmd",
    "extract_cmd",
    "summary_cmd",
    "kb_cmd",
    "annotate_cmd",
    "export_cmd",
    "verify_hash_cmd",
    "identify_cmd",
    "validate_tool_cmd",
    "redact_errors_cmd",
)

# Subcommand name → handler module name.
_DISPATCH = {
    "acquire":       "acquire_cmd",
    "extract":       "extract_cmd",
    "summary":       "summary_cmd",
    "kb":            "kb_cmd",
    "annotate":      "annotate_cmd",
    "export":        "export_cmd",
    "verify-hash":   "verify_hash_cmd",
    "identify":      "identify_cmd",
    "validate-tool": "validate_tool_cmd",
    "redact-errors": "redact_errors_cmd",
}


def _build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="forensic-aul",
        description="Forensic Apple Unified Log parser — converts an acquisition to SQLite.",
    )
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    root.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show DEBUG messages on the console (log file always INFO).",
    )

    sub = root.add_subparsers(dest="command", metavar="COMMAND")
    # Not required: invocation with no subcommand launches the GUI (see main()).
    sub.required = False

    for mod_name in _COMMAND_MODULES:
        module = importlib.import_module(f"launcher.cmds.{mod_name}")
        module.add_subcommand(sub)

    return root


def main() -> None:
    # Minimal bootstrap logging (console only, INFO) so that any errors
    # that occur before a command sets up its own logging are still visible.
    logging.basicConfig(
        format="%(asctime)s  %(levelname)-8s — %(message)s",
        datefmt="%H:%M:%S",
        level=logging.INFO,
    )

    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        from launcher.gui import run_gui
        sys.exit(run_gui())

    # Install the crash handler for the CLI now that the command is known. It
    # catches exceptions that propagate out of a command; the commands that
    # catch-log-and-return also report directly (see app.diagnostics).
    from app.diagnostics import install_excepthook
    install_excepthook({"entrypoint": "cli", "command": args.command})

    # Dispatch to the handler module's run(args). The subparser guarantees
    # args.command is one of the registered names.
    module = importlib.import_module(f"launcher.cmds.{_DISPATCH[args.command]}")
    sys.exit(module.run(args))


if __name__ == "__main__":
    main()
