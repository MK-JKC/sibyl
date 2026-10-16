"""``sibyl`` command line (Apache-2; no control-plane imports).

``sibyl audit verify <export.jsonl> --public-key <keys> [--anchor <anchor.json>]`` verifies an
exported audit chain offline (R33). Run as ``python -m sibyl.cli``; the ``sibyl`` console
script is a CHANGE REQUEST on the SDK's ``pyproject.toml`` (``[project.scripts] sibyl =
"sibyl.cli:main"``).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import audit

EXIT_OK = 0
EXIT_BREAK = 1
EXIT_INPUT = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sibyl", description="Sibyl command line")
    groups = parser.add_subparsers(dest="group", required=True)
    audit_cmd = groups.add_parser("audit", help="audit chain tools")
    verbs = audit_cmd.add_subparsers(dest="verb", required=True)
    verify = verbs.add_parser(
        "verify", help="verify an exported audit chain offline against signed anchors"
    )
    verify.add_argument("export", type=Path, help="export JSONL (sibyl.audit_export/1)")
    verify.add_argument(
        "--public-key",
        dest="public_keys",
        type=Path,
        action="append",
        required=True,
        help="audit-anchor public key or key set (PEM, base64url, or JSON); repeatable",
    )
    verify.add_argument(
        "--anchor",
        dest="anchors",
        type=Path,
        action="append",
        default=[],
        help="anchor JSON (object, list, {data: [...]} or JSONL); default: the export's own",
    )
    verify.add_argument(
        "--expected-to-seq",
        type=int,
        help="terminal sequence obtained independently of the export",
    )
    verify.add_argument(
        "--expected-head-hash",
        help="64-hex-character terminal digest independently pinned by the auditor",
    )
    verify.add_argument("--quiet", action="store_true", help="no summary on stderr")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.group == "audit" and args.verb == "verify":
        try:
            report = audit.verify_files(
                args.export,
                args.public_keys,
                args.anchors,
                expected_to_seq=args.expected_to_seq,
                expected_head_hash=args.expected_head_hash,
            )
        except audit.InputError as exc:
            sys.stderr.write(f"sibyl audit verify: cannot verify: {exc}\n")
            return EXIT_INPUT
        sys.stdout.write(audit.render(report) + "\n")
        if not args.quiet:
            if report.ok:
                sys.stderr.write(
                    f"OK: {report.rows} rows (seq {report.from_seq}..{report.to_seq}),"
                    f" {report.anchors_checked} anchor(s) verified\n"
                )
            else:
                sys.stderr.write(
                    f"BROKEN at seq {report.first_break_seq}: {report.kind} ({report.detail})\n"
                )
        return EXIT_OK if report.ok else EXIT_BREAK
    return EXIT_INPUT  # pragma: no cover - argparse requires a known verb


__all__ = ["EXIT_BREAK", "EXIT_INPUT", "EXIT_OK", "main"]
