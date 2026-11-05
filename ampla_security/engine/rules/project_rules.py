from __future__ import annotations

import re
from typing import Any

from ampla_security.engine.finding import Finding, FindingLocation


class MissingPermissionRule:
    """
    Detects missing or undefined permissions in project configuration.
    Derived from Project.Security.xslt patterns.
    """

    category: str = "project"
    priority: int = 2
    match: str = "//Item"

    def apply(self, context: Any) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        scope_ids = set(context.scopes.keys())

        for item in context.find(self.match):
            item_id = item.get("id")
            item_name = (
                item.get("fullName") or item.get("name") or item_id or "<unknown>"
            )

            inherit_prop = item.find("Property[@name='InheritPermissions']")
            if (
                inherit_prop is not None
                and (inherit_prop.text or "").strip().lower() == "false"
            ):
                scope_props = item.xpath(
                    "Property[@name='ScopeId' or @name='SecurityScope' or @name='Scope']"
                )
                item_links = item.xpath("ItemLink[@targetID]")

                if not scope_props and not item_links:
                    findings.append(
                        {
                            "severity": "Warning",
                            "message": (
                                f"Item '{item_name}' has inheritance disabled but no explicit permission scope assignment."
                            ),
                            "itemId": item_id,
                        }
                    )
                else:
                    for prop in scope_props:
                        value = (prop.text or "").strip()
                        if not value:
                            findings.append(
                                {
                                    "severity": "Warning",
                                    "message": (
                                        f"Item '{item_name}' defines a scope property '{prop.get('name')}' with no value."
                                    ),
                                    "itemId": item_id,
                                }
                            )
                        elif scope_ids and value not in scope_ids:
                            findings.append(
                                {
                                    "severity": "Error",
                                    "message": (
                                        f"Item '{item_name}' references unknown scope '{value}' in property '{prop.get('name')}'."
                                    ),
                                    "itemId": item_id,
                                }
                            )

                    for link in item_links:
                        target_id = link.get("targetID")
                        if target_id and scope_ids and target_id not in scope_ids:
                            findings.append(
                                {
                                    "severity": "Error",
                                    "message": (
                                        f"Item '{item_name}' links to unknown permission scope target '{target_id}'."
                                    ),
                                    "itemId": item_id,
                                }
                            )

            # User identity validation
            if item.get("type") == "Citect.Ampla.StandardItems.User":
                has_identity = bool(
                    item.get("sid")
                    or item.find("Property[@name='SecurityID']") is not None
                    or item.find("Property[@name='Identity']/Identity") is not None
                )
                if not has_identity:
                    findings.append(
                        {
                            "severity": "Warning",
                            "message": (
                                f"User '{item_name}' is missing a security identifier and may have incomplete permission assignments."
                            ),
                            "itemId": item_id,
                        }
                    )

        return findings


class WeakAuthenticationConfigRule:
    """
    Flags insecure authentication configuration patterns.
    """

    category: str = "project"
    priority: int = 1
    match: str = "//Item[@type='Citect.Ampla.StandardItems.User']"

    def apply(self, context: Any) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for user_item in context.find(self.match):
            auth_prop = user_item.find("Property[@name='Authentication']")
            auth_value = (
                auth_prop.text.strip()
                if auth_prop is not None and auth_prop.text
                else ""
            )

            if not auth_value or auth_value.lower() in {"none", "password", "disabled"}:
                findings.append(
                    {
                        "severity": "Warning",
                        "message": (
                            f"User '{user_item.get('name') or user_item.get('id')}' has weak or missing authentication configuration."
                        ),
                        "itemId": user_item.get("id"),
                    }
                )

        return findings


class ExposedConfigurationDataRule:
    """
    Detects sensitive configuration values exposed in project XML.
    """

    category: str = "project"
    priority: int = 1
    match: str = "//Item"

    sensitive_name_keywords: set[str] = {
        "password",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "credential",
        "connectionstring",
        "connstr",
        "accesskey",
        "secretkey",
    }

    sensitive_value_patterns: list[re.Pattern[str]] = [
        re.compile(r"\b(password|pwd)\s*[=:]", re.IGNORECASE),
        re.compile(r"\b(api[_-]?key|secret|token)\s*[=:]", re.IGNORECASE),
        re.compile(r"\bbearer\s+[A-Za-z0-9\-\.\_]+", re.IGNORECASE),
        re.compile(r"\buser(id|name)?\s*[=:].*password\s*[=:]", re.IGNORECASE),
        re.compile(r"\b(password|pwd)\s*=\s*[^;]+;", re.IGNORECASE),
        re.compile(
            r"\b(mysql|postgresql|mssql|sqlserver|oracle)://[^\s]+:[^\s]+@",
            re.IGNORECASE,
        ),
    ]

    sensitive_path_patterns: list[re.Pattern[str]] = [
        re.compile(r"(^|[\\/])tmp([\\/]|$)", re.IGNORECASE),
        re.compile(r"(^|[\\/])var[\\/]tmp([\\/]|$)", re.IGNORECASE),
        re.compile(r"[\\/]AppData[\\/]Local[\\/]Temp([\\/]|$)", re.IGNORECASE),
        re.compile(r"[A-Za-z]:(?:\\|/).*?(?:temp|tmp)(?:\\|/|$)", re.IGNORECASE),
        re.compile(r"[\\/]\.ssh([\\/]|$)", re.IGNORECASE),
    ]

    rule_id = "exposed-configuration-data"

    def apply(self, context: Any) -> list[Finding]:
        findings: list[Finding] = []
        occurrences: dict[tuple[str, str], int] = {}

        for item in context.find(self.match):
            item_id = item.get("id")
            item_path = item.getroottree().getpath(item)

            for prop in item.findall("Property"):
                prop_name = (prop.get("name") or "").strip()
                prop_value = (prop.text or "").strip()
                if not prop_value:
                    continue

                if self.is_sensitive_name(prop_name) or self.is_sensitive_value(
                    prop_value
                ):
                    key = (item_path, prop_name)
                    occurrence = occurrences.get(key, 0) + 1
                    occurrences[key] = occurrence
                    findings.append(
                        Finding.create(
                            rule_id=self.rule_id,
                            severity="warning",
                            title="Potentially sensitive configuration data",
                            message=(
                                "A project property matched a sensitive-data "
                                "detection heuristic. The property value is not "
                                "included."
                            ),
                            source_stage="project-input",
                            location=FindingLocation(
                                item_id=item_id,
                                item_path=item_path,
                                property_name=prop_name or None,
                            ),
                            occurrence=occurrence,
                        )
                    )

        return findings

    def is_sensitive_name(self, prop_name: str) -> bool:
        prop_name_lower = prop_name.replace(" ", "").lower()
        if prop_name_lower in self.sensitive_name_keywords:
            return True
        tokens = set(re.findall(r"[a-z0-9]+", prop_name_lower))
        return bool(tokens & self.sensitive_name_keywords)

    def is_sensitive_value(self, prop_value: str) -> bool:
        if any(pattern.search(prop_value) for pattern in self.sensitive_value_patterns):
            return True
        if any(pattern.search(prop_value) for pattern in self.sensitive_path_patterns):
            return True
        return False


class MissingRoleAssignmentRule:
    """
    Detects roles that exist but are not assigned to any user or group.
    """

    category: str = "project"
    priority: int = 1
    match: str = "//Role"

    def apply(self, context: Any) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for role in context.find(self.match):
            role_id = role.get("roleId")
            role_name = role.get("name") or role_id or "<unknown>"
            members = role.findall("Member")

            if not members:
                findings.append(
                    {
                        "severity": "Warning",
                        "message": f"Role '{role_name}' has no members assigned.",
                        "itemId": role_id,
                    }
                )
                continue

            invalid_members: list[Any] = []
            unresolved_members: list[Any] = []

            for member in members:
                sid = (member.get("sid") or "").strip()
                if not sid:
                    invalid_members.append(member)
                    continue

                member_type = member.get("type", "unknown").lower()
                user_node = member.find("User")
                user_has_name = user_node is not None and bool(
                    (user_node.get("name") or "").strip()
                )

                if member_type == "unknown" and not user_has_name:
                    unresolved_members.append(member)

            if invalid_members:
                for member in invalid_members:
                    findings.append(
                        {
                            "severity": "Error",
                            "message": (
                                f"Role '{role_name}' contains an invalid member definition with missing SID."
                            ),
                            "itemId": role_id,
                        }
                    )

            if unresolved_members and len(unresolved_members) == len(members):
                findings.append(
                    {
                        "severity": "Warning",
                        "message": (
                            f"Role '{role_name}' only references unknown or unresolved members."
                        ),
                        "itemId": role_id,
                    }
                )

        return findings
