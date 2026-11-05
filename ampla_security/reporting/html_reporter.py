from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from lxml.etree import _Element, _ElementTree


class HtmlReporter:
    """
    Renders the legacy Security document or the findings-based report template.
    """

    def __init__(self, findings: list[Any] | _ElementTree | _Element):
        if isinstance(findings, _ElementTree):
            security_root = findings.getroot()
        elif isinstance(findings, _Element):
            security_root = findings
        else:
            security_root = None

        if security_root is not None and security_root.tag != "Security":
            raise ValueError("Security report input must have a Security root")

        self.security_root = security_root
        self.findings = findings if security_root is None else []
        self.template_dir = Path(__file__).resolve().parent / "templates"

    def generate(self, output_path: str | Path) -> None:
        if self.security_root is not None:
            html = self._render_security_report()
        else:
            base_template = self._load_template("base.html")
            report_template = self._load_template("security_report.html")
            report_content = self._render_report_template(report_template)
            html = base_template.replace("{{ content }}", report_content)

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

    def _render_security_report(self) -> str:
        if self.security_root is None:
            raise ValueError("Security report input must have a Security root")

        body = [
            '<div class="header">',
            "<h1>Ampla Project Summary - Security</h1>",
            "<hr/>",
            "</div>",
            '<span class="menu"><a href="#roles">Roles</a></span>',
            '<span class="menu"><a href="#scopes">Scopes</a></span>',
            '<span class="menu"><a href="#users">Users</a></span>',
            "<hr/>",
            '<a name="roles"></a>',
            "<h2>Roles</h2>",
            self._build_role_table(),
            "<br/>",
            "<hr/>",
            '<a name="scopes"></a>',
            "<h2>Security Scopes</h2>",
            self._build_scope_table(self.security_root.xpath("./Scopes/Scope[@valid]")),
        ]
        invalid_scopes = self.security_root.xpath("./Scopes/Scope[@invalid]")
        if invalid_scopes:
            body.extend(
                [
                    "<br/>",
                    "<hr/>",
                    "<h2>Errors in Security Scopes</h2>",
                    self._build_scope_table(invalid_scopes),
                ]
            )
        body.extend(
            [
                "<br/>",
                "<hr/>",
                '<a name="users"></a>',
                "<h2>User Role Assignments</h2>",
                self._build_user_table(invalid_scopes),
            ]
        )

        return "\n".join(
            [
                '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" '
                '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">',
                "<html>",
                "<head>",
                '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>',
                "<title>Ampla Project Summary - Security</title>",
                '<link rel="stylesheet" type="text/css" href="css/security.css" '
                'media="screen,projector"/>',
                "</head>",
                "<body>",
                *body,
                "</body>",
                "</html>",
            ]
        )

    def _build_role_table(self) -> str:
        if self.security_root is None:
            raise ValueError("Security report input must have a Security root")

        roles = self.security_root.xpath("./RoleDefinitions/RoleDefinition")
        operations = self.security_root.xpath("./Operations/Operation")
        rows = ["<table>", "<tbody>", "<tr>", "<th>Operation</th>"]
        rows.extend(
            '<th><span class="role" title="{}">{}</span></th>'.format(
                self._escape_attribute(role.get("description", "")),
                self._escape_text(role.get("name", "")),
            )
            for role in roles
        )
        rows.append("</tr>")

        for operation in operations:
            operation_name = operation.get("name", "")
            rows.extend(
                [
                    "<tr>",
                    '<td><span class="operation row-head" title="{}">{}</span></td>'.format(
                        self._escape_attribute(operation.get("description", "")),
                        self._escape_text(operation_name),
                    ),
                ]
            )
            for role in roles:
                allowed = "name" in operation.attrib and bool(
                    role.xpath(
                        ".//Operation[@name=$operation_name]",
                        operation_name=operation_name,
                    )
                )
                assignment_class = "allowed" if allowed else "denied"
                value = "Y" if allowed else "."
                rows.append(
                    '<td class="center {}"><span title="{}">{}</span></td>'.format(
                        assignment_class, assignment_class, value
                    )
                )
            rows.append("</tr>")

        rows.extend(["</tbody>", "</table>"])
        return "\n".join(rows)

    def _build_scope_table(self, scopes: list[_Element]) -> str:
        if self.security_root is None:
            raise ValueError("Security report input must have a Security root")

        roles = self.security_root.xpath("./RoleDefinitions/RoleDefinition")
        rows = ["<table>", "<tbody>", "<tr>", "<th>Scope</th>"]
        rows.extend(
            '<th><span class="role" title="{}">{}</span></th>'.format(
                self._escape_attribute(role.get("description", "")),
                self._escape_text(role.get("name", "")),
            )
            for role in roles
        )
        rows.append("</tr>")

        for scope in scopes:
            scope_name = scope.get("name", "")
            invalid_message = scope.get("invalid")
            rows.extend(
                [
                    "<tr>",
                    '<td><span class="scope row-head">{}</span>'.format(
                        self._escape_text(scope_name)
                    ),
                ]
            )
            if invalid_message is not None:
                rows.extend(
                    [
                        "<br/>",
                        '<span class="warning">{}</span>'.format(
                            self._escape_text(invalid_message)
                        ),
                    ]
                )
            rows.append("</td>")

            for role in roles:
                role_id = role.get("roleId")
                assignments = (
                    scope.xpath("./Role[@roleId=$role_id]/Member", role_id=role_id)
                    if role_id is not None
                    else []
                )
                assignment_class = "allowed" if assignments else "denied"
                cell = ['<td class="{}">'.format(assignment_class)]
                if assignments:
                    assigned_users = [
                        user
                        for member in assignments
                        for user in member.xpath("./User")
                    ]
                    assigned_users.sort(key=lambda user: user.get("name", "") + "ZZZ")
                    cell.append('<ul class="assignment">')
                    cell.extend(
                        self._render_role_assignment(user) for user in assigned_users
                    )
                    cell.append("</ul>")
                cell.append("</td>")
                rows.append("\n".join(cell))
            rows.append("</tr>")

        rows.extend(["</tbody>", "</table>"])
        return "\n".join(rows)

    def _render_role_assignment(self, user: _Element) -> str:
        member = user.getparent()
        member_type = member.get("type", "") if member is not None else ""
        has_name = "name" in user.attrib
        if has_name:
            display_name = user.get("name", "")
            user_class = "user"
            title_user = ""
        else:
            display_name = f"unknown {member_type} user"
            user_class = "warning user"
            title_user = "".join(user.itertext())
        title = f" [{member_type}] {title_user}"
        result = [
            '<li title="{}">'.format(self._escape_attribute(title)),
            '<span class="{}">{}</span>'.format(
                user_class, self._escape_text(display_name)
            ),
        ]
        identities = user.xpath("./Identity/@name")
        if identities:
            result.extend(
                [
                    "<br/>",
                    '<span class="identity">({})</span>'.format(
                        self._escape_text(str(identities[0]))
                    ),
                ]
            )
        result.append("</li>")
        return "\n".join(result)

    def _build_user_table(self, invalid_scopes: list[_Element]) -> str:
        if self.security_root is None:
            raise ValueError("Security report input must have a Security root")

        users = self.security_root.xpath("./Users/User")
        all_scopes = self.security_root.xpath("./Scopes/Scope")
        rows = [
            "<table>",
            "<tbody>",
            "<tr>",
            '<th rowspan="2">Users</th>',
            '<th rowspan="2">Authentication</th>',
            '<th rowspan="2">Ampla Security</th>',
            '<th rowspan="2">Windows Identity</th>',
            '<th colspan="3">Role Assignments</th>',
            "</tr>",
            "<tr>",
            '<th class="allowed">Allowed</th>',
            '<th class="denied">Denied</th>',
        ]
        if invalid_scopes:
            rows.append("<th>Invalid</th>")
        rows.append("</tr>")

        for user in users:
            rows.extend(
                [
                    "<tr>",
                    '<td><span class="user row-head">{}</span>'.format(
                        self._escape_text(user.get("name", ""))
                    ),
                ]
            )
            user_invalid = user.get("invalid")
            if user_invalid is not None:
                rows.extend(
                    [
                        "<br/>",
                        '<span class="warning">{}</span>'.format(
                            self._escape_text(user_invalid)
                        ),
                    ]
                )
            rows.append("</td>")
            rows.append(
                "<td>{}</td>".format(
                    self._escape_text(
                        str(user.xpath("string(Property[@name='Authentication'][1])"))
                    )
                )
            )
            rows.append(
                "<td>{}</td>".format(
                    self._escape_text(
                        str(user.xpath("string(Property[@name='SecurityID'][1])"))
                    )
                )
            )
            rows.append(
                "<td>{}</td>".format(
                    self._escape_text(
                        str(
                            user.xpath(
                                "string(Property[@name='Identity']/Identity/@name)"
                            )
                        )
                    )
                )
            )

            user_id = user.get("id")
            if user_id is None:
                assigned_scopes: list[_Element] = []
            else:
                assigned_scopes = [
                    scope
                    for scope in all_scopes
                    if scope.xpath("Role/Member/User[@id=$user_id]", user_id=user_id)
                ]

            valid_assigned = [
                scope for scope in assigned_scopes if "valid" in scope.attrib
            ]
            valid_scopes = [scope for scope in all_scopes if "valid" in scope.attrib]
            invalid_assigned = [
                scope for scope in assigned_scopes if "invalid" in scope.attrib
            ]
            rows.append(
                self._render_scope_list_cell(
                    valid_assigned, [], user_id, "allowed", "denied"
                )
            )
            rows.append(
                self._render_scope_list_cell(
                    valid_scopes,
                    valid_assigned,
                    user_id,
                    "denied",
                    None,
                )
            )
            if invalid_scopes:
                rows.append(
                    self._render_scope_list_cell(
                        invalid_assigned, [], user_id, "warning", None
                    )
                )
            rows.append("</tr>")

        rows.extend(["</tbody>", "</table>"])
        return "\n".join(rows)

    def _render_scope_list_cell(
        self,
        scopes: list[_Element],
        except_scopes: list[_Element],
        user_id: str | None,
        assignment_class: str,
        none_class: str | None,
    ) -> str:
        if not (len(scopes) > 0 and len(scopes) > len(except_scopes)):
            return '<td class="{}"></td>'.format(none_class or "")

        ordered_scopes = sorted(
            scopes,
            key=lambda scope: (
                scope.get("invalid", ""),
                scope.get("valid", ""),
                scope.get("name", ""),
            ),
        )
        except_scope_ids = {
            scope.get("scopeId") for scope in except_scopes if "scopeId" in scope.attrib
        }
        rendered = ['<td class="{}">'.format(assignment_class), "<ul>"]
        for scope in ordered_scopes:
            scope_id = scope.get("scopeId")
            if scope_id is not None and scope_id in except_scope_ids:
                continue

            invalid_message = scope.get("invalid")
            scope_name = self._escape_text(scope.get("name", ""))
            if invalid_message is not None:
                rendered.append(
                    '<li><span class="scope warning" title="{}">{}</span>'.format(
                        self._escape_attribute(invalid_message), scope_name
                    )
                )
            else:
                rendered.append('<li><span class="scope">{}</span>'.format(scope_name))

            assigned_roles = []
            if user_id is not None:
                assigned_roles = scope.xpath(
                    "Role[Member/User[@id=$user_id]]", user_id=user_id
                )
            if assigned_roles:
                rendered.append("<ul>")
                rendered.extend(
                    '<li><span class="{}">{}</span></li>'.format(
                        assignment_class,
                        self._escape_text(role.get("name", "")),
                    )
                    for role in assigned_roles
                )
                rendered.append("</ul>")
            rendered.append("</li>")
        rendered.extend(["</ul>", "</td>"])
        return "\n".join(rendered)

    def _load_template(self, filename: str) -> str:
        path = self.template_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Missing template: {filename}")
        return path.read_text(encoding="utf-8")

    def _render_report_template(self, template: str) -> str:
        lines: list[str] = []
        in_loop = False

        for line in template.splitlines():
            stripped = line.strip()

            if stripped.startswith("{% for finding in findings %}"):
                in_loop = True
                continue

            if stripped.startswith("{% endfor %}"):
                in_loop = False
                continue

            if in_loop:
                if "{{ finding.severity }}" in line or "{{ finding.message }}" in line:
                    for finding in self.findings:
                        item_html = line

                        severity = (
                            finding.get("severity")
                            if isinstance(finding, dict)
                            else getattr(finding, "severity", "")
                        )
                        message = (
                            finding.get("message")
                            if isinstance(finding, dict)
                            else getattr(finding, "message", "")
                        )

                        item_html = item_html.replace(
                            "{{ finding.severity }}",
                            self._escape(self._to_text(severity)),
                        )
                        item_html = item_html.replace(
                            "{{ finding.message }}",
                            self._escape(self._to_text(message)),
                        )

                        lines.append(item_html)
                    continue

            lines.append(line)

        return "\n".join(lines)

    def _escape(self, value: str) -> str:
        return escape(value, quote=True)

    def _escape_text(self, value: str) -> str:
        return escape(value, quote=False)

    def _escape_attribute(self, value: str) -> str:
        return escape(value, quote=True)

    def _to_text(self, value: Any) -> str:
        return "" if value is None else str(value)
