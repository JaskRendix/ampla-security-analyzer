from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

Severity = Literal["error", "warning", "info"]


@dataclass(frozen=True)
class FindingLocation:
    item_id: str | None = None
    item_path: str | None = None
    property_name: str | None = None
    role_id: str | None = None
    scope_id: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "itemId": self.item_id,
            "itemPath": self.item_path,
            "propertyName": self.property_name,
            "roleId": self.role_id,
            "scopeId": self.scope_id,
        }


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    severity: Severity
    title: str
    message: str
    source_stage: str
    location: FindingLocation

    def __post_init__(self) -> None:
        if self.severity not in {"error", "warning", "info"}:
            raise ValueError(f"Unsupported finding severity: {self.severity}")

    @classmethod
    def create(
        cls,
        *,
        rule_id: str,
        severity: Severity,
        title: str,
        message: str,
        source_stage: str,
        location: FindingLocation,
        occurrence: int = 1,
    ) -> Finding:
        identity = json.dumps(
            [
                rule_id,
                source_stage,
                location.item_id,
                location.item_path,
                location.property_name,
                location.role_id,
                location.scope_id,
                occurrence,
            ],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
        finding_id = f"{rule_id}:{digest}"
        return cls(
            id=finding_id,
            rule_id=rule_id,
            severity=severity,
            title=title,
            message=message,
            source_stage=source_stage,
            location=location,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "ruleId": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "sourceStage": self.source_stage,
            "location": self.location.to_dict(),
        }


def serialize_findings(findings: list[Finding]) -> str:
    severity_order = {"error": 0, "warning": 1, "info": 2}
    ordered = sorted(
        findings,
        key=lambda finding: (
            severity_order[finding.severity],
            finding.rule_id,
            finding.location.item_id or "",
            finding.location.item_path or "",
            finding.location.property_name or "",
            finding.id,
        ),
    )
    counts = {
        severity: sum(finding.severity == severity for finding in ordered)
        for severity in ("error", "warning", "info")
    }
    payload = {
        "schemaVersion": "1.0",
        "summary": {
            "total": len(ordered),
            "bySeverity": counts,
        },
        "findings": [finding.to_dict() for finding in ordered],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
