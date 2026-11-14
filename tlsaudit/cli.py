"""Command line entry point.

    python -m tlsaudit.cli --dir demo/openssl_cfgs --out out/report.json
"""

from __future__ import annotations

import argparse
import os
import sys

from .config import ConfigError, load_config
from .parser import CipherStringError
from .report import Issue, Report, summarize, write_json
from .rules import evaluate


def _iter_config_files(directory: str):
    for entry in sorted(os.listdir(directory)):
        path = os.path.join(directory, entry)
        if os.path.isfile(path) and not entry.startswith("."):
            yield path


def audit_directory(directory: str):
    reports = []
    for path in _iter_config_files(directory):
        try:
            config = load_config(path)
            reports.append(evaluate(config))
        except (ConfigError, CipherStringError) as exc:
            reports.append(
                Report(
                    file=path,
                    enabled_protocols=[],
                    enabled_ciphers=[],
                    aead_available=False,
                    seclevel=None,
                    issues=[Issue("parse_error", str(exc), "critical")],
                )
            )
    return reports


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="tlsaudit",
        description="Audit OpenSSL-style TLS configuration files.",
    )
    parser.add_argument("--dir", required=True, help="directory of config files")
    parser.add_argument("--out", help="write the JSON report to this path")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.dir):
        print(f"error: {args.dir!r} is not a directory", file=sys.stderr)
        return 2

    reports = audit_directory(args.dir)
    if args.out:
        write_json(reports, args.out)

    summary = summarize(reports)
    distribution = ", ".join(
        f"{name}={count}" for name, count in summary["issue_types"].items()
    ) or "none"
    print(
        f"Audited {summary['config_count']} config(s): "
        f"{summary['issue_count']} issue(s) [{distribution}]"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

