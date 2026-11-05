from __future__ import annotations

from pathlib import Path

from lxml.etree import _Element, _ElementTree


class SecurityTextReporter:
    """Generates the legacy roles and assignments reports from a Security tree."""

    HEADER = "=" * 40
    SEPARATOR = "-" * 40
    CRLF = "\r\n"

    def __init__(self, security: _ElementTree | _Element):
        root = security.getroot() if isinstance(security, _ElementTree) else security
        if root.tag != "Security":
            raise ValueError("Security text report input must have a Security root")
        self.security_root = root

    def generate(
        self,
        roles_output_path: str | Path,
        assignments_output_path: str | Path,
    ) -> None:
        self._write(self.render_roles(), roles_output_path)
        self._write(self.render_assignments(), assignments_output_path)

    def render_roles(self) -> str:
        roles = sorted(
            self.security_root.xpath("./RoleDefinitions/RoleDefinition"),
            key=lambda role: role.get("name", ""),
        )
        operations = sorted(
            self.security_root.xpath("./Operations/Operation"),
            key=lambda operation: operation.get("name", ""),
        )
        output: list[str] = []

        for role in roles:
            role_name = role.get("name", "")
            output.extend(
                [
                    self.CRLF,
                    self.HEADER,
                    self.CRLF,
                    f"Role: '{role_name}'",
                    self.CRLF,
                    f"      ({role.get('description', '')})",
                    self.CRLF,
                    self.SEPARATOR,
                ]
            )
            for operation in operations:
                operation_name = operation.get("name", "")
                if "name" in operation.attrib and role.xpath(
                    ".//Operation[@name=$operation_name]",
                    operation_name=operation_name,
                ):
                    output.extend(
                        [
                            self.CRLF,
                            f"+  Operation: '{operation_name}'",
                        ]
                    )
            output.extend([self.CRLF, self.HEADER, self.CRLF])

        output.append(self.CRLF)
        return "".join(output)

    def render_assignments(self) -> str:
        users = sorted(
            self.security_root.xpath("./Users/User"),
            key=lambda user: user.get("name", ""),
        )
        scopes = self.security_root.xpath("./Scopes/Scope")
        output: list[str] = []

        for user in users:
            user_id = user.get("id")
            user_scopes = (
                self.security_root.xpath(
                    "./Scopes/Scope[Role/Member/User[@id=$user_id]]",
                    user_id=user_id,
                )
                if user_id is not None
                else []
            )
            user_role_names = {
                role.get("name")
                for scope in user_scopes
                for role in scope.xpath(
                    "Role[Member/User[@id=$user_id]]", user_id=user_id
                )
                if "name" in role.attrib
            }
            roles = sorted(
                (
                    role
                    for role in self.security_root.xpath(
                        "./RoleDefinitions/RoleDefinition"
                    )
                    if "name" in role.attrib and role.get("name") in user_role_names
                ),
                key=lambda role: role.get("name", ""),
            )
            user_scope_names = {
                scope.get("name") for scope in user_scopes if "name" in scope.attrib
            }
            denied_scopes = sorted(
                (
                    scope
                    for scope in scopes
                    if "valid" in scope.attrib
                    and (
                        "name" not in scope.attrib
                        or scope.get("name") not in user_scope_names
                    )
                ),
                key=lambda scope: scope.get("name", ""),
            )

            output.extend(
                [
                    self.CRLF,
                    self.HEADER,
                    self.CRLF,
                    f"User: '{user.get('name', '')}'",
                    self.CRLF,
                    "      Authentication = ",
                    self._property_text(user, "Authentication"),
                ]
            )
            identities = user.xpath("./Property/Identity")
            if identities:
                output.extend(
                    [
                        self.CRLF,
                        "      Identity = ",
                        identities[0].get("name", ""),
                    ]
                )
            output.extend([self.CRLF, self.SEPARATOR])

            for role in roles:
                role_name = role.get("name", "")
                output.extend(
                    [
                        self.CRLF,
                        f"+  Role: '{role_name}'",
                    ]
                )
                scopes_for_role = sorted(
                    (
                        scope
                        for scope in user_scopes
                        if "name" in role.attrib
                        and scope.xpath("Role[@name=$role_name]", role_name=role_name)
                    ),
                    key=lambda scope: scope.get("name", ""),
                )
                for scope in scopes_for_role:
                    output.extend(
                        [
                            self.CRLF,
                            f"   {scope.get('name', '')}",
                        ]
                    )

            output.extend([self.CRLF, "+  [Denied]"])
            for scope in denied_scopes:
                output.extend(
                    [
                        self.CRLF,
                        f"   {scope.get('name', '')}",
                    ]
                )
            output.extend([self.CRLF, self.HEADER, self.CRLF])

        return "".join(output)

    @staticmethod
    def _property_text(user: _Element, property_name: str) -> str:
        return str(user.xpath("string(Property[@name=$name])", name=property_name))

    @staticmethod
    def _write(content: str, output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
