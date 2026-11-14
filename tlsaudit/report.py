"""Report data structures and JSON serialisation."""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Issue:
    name: str
    evidence: str
    severity: str

    def to_dict(self) -> dict:
        return {"name": self.name, "evidence": self.evidence, "severity": self.severity}


@dataclass
class Report:
    file: str
    enabled_protocols: list
    enabled_ciphers: list
    aead_available: bool
    seclevel: object  # int or None
    issues: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "enabled_protocols": list(self.enabled_protocols),
            "enabled_ciphers": list(self.enabled_ciphers),
            "aead_available": self.aead_available,
            "seclevel": self.seclevel,
            "issues": [issue.to_dict() for issue in self.issues],
        }


def summarize(reports) -> dict:
    distribution = Counter()
    total_issues = 0
    for report in reports:
        for issue in report.issues:
            distribution[issue.name] += 1
            total_issues += 1
    return {
        "config_count": len(reports),
        "issue_count": total_issues,
        "issue_types": dict(sorted(distribution.items())),
    }


def build_document(reports) -> dict:
    return {
        "summary": summarize(reports),
        "configs": [report.to_dict() for report in reports],
    }


def write_json(reports, out_path) -> None:
    directory = os.path.dirname(os.path.abspath(out_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(build_document(reports), handle, indent=2, ensure_ascii=False)
        handle.write("\n")

