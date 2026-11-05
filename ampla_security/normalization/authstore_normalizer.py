from __future__ import annotations

from typing import Any

from lxml import etree
from lxml.etree import _Element, _ElementTree

from ampla_security.xml.utils import copy_node


class AuthstoreNormalizer:
    """
    Converts AuthStore XML and project security data to the legacy Security schema.
    """

    def __init__(self, xml_tree: _ElementTree):
        self.tree: _ElementTree = xml_tree
        self.root: _Element = xml_tree.getroot()
        self.project_security_root: _Element | None = None

    def set_project_security(self, project_security: _ElementTree | _Element) -> None:
        root = (
            project_security.getroot()
            if isinstance(project_security, _ElementTree)
            else project_security
        )
        if root.tag != "Security":
            raise ValueError("Project security input must have a Security root")
        self.project_security_root = root

    def normalize(self) -> _ElementTree:
        normalized_root = self.normalize_authstore_root(self.root)
        return etree.ElementTree(normalized_root)

    def normalize_authstore_root(self, authstore_root: _Element) -> _Element:
        if authstore_root.tag == "AzAdminManager":
            applications = authstore_root.xpath("AzApplication")
        elif authstore_root.tag == "AzApplication":
            applications = [authstore_root]
        else:
            raise ValueError(
                f"Unsupported AuthStore root element: {authstore_root.tag}"
            )

        if len(applications) != 1:
            raise ValueError("AuthStore input must contain exactly one AzApplication")
        return self.normalize_authorization_application(applications[0])

    def normalize_authorization_application(self, app_node: _Element) -> _Element:
        normalized = etree.Element("Security")
        normalized.set("name", app_node.get("Name", ""))

        operations = etree.SubElement(normalized, "Operations")
        for operation in sorted(
            app_node.xpath("AzOperation"), key=self._operation_sort_key
        ):
            operations.append(self.normalize_operation(operation))

        role_definitions = etree.SubElement(normalized, "RoleDefinitions")
        for task in app_node.xpath("AzTask[@RoleDefinition='True']"):
            role_definitions.append(self.normalize_role_definition(task))

        scopes = etree.SubElement(normalized, "Scopes")
        global_scope = etree.SubElement(scopes, "Scope")
        global_scope.set("name", "{Global}")
        global_scope.set("scopeId", "00000000-0000-0000-0000-000000000000")
        global_scope.set("valid", "Default scope")
        for role in app_node.xpath("AzRole"):
            global_scope.append(self.normalize_role(role))
        for scope in app_node.xpath("AzScope"):
            scopes.append(self.normalize_scope(scope))
        self.add_project_scopes(app_node, scopes)

        users = etree.SubElement(normalized, "Users")
        if self.project_security_root is not None:
            project_users = self.project_security_root.xpath("./Users/User")
            for user in sorted(project_users, key=self._project_user_sort_key):
                users.append(self.normalize_project_user(user))

        return normalized

    def add_project_scopes(self, app_node: _Element, scopes_node: _Element) -> None:
        if self.project_security_root is None:
            return

        authstore_scope_ids = set(app_node.xpath("AzScope/@Name"))
        for project_scope in self.project_security_root.xpath("./Scopes/Scope[@id]"):
            scope_id = project_scope.get("scopeId", "")
            if scope_id in authstore_scope_ids:
                continue

            missing_scope = etree.SubElement(scopes_node, "Scope")
            missing_scope.set("name", project_scope.get("fullName", ""))
            missing_scope.set("scopeId", scope_id)
            missing_scope.set(
                "invalid",
                "Warning: Scope does not exist in Authorization Store (AuthStore.xml)",
            )

    def _operation_sort_key(self, operation: _Element) -> tuple[int, float]:
        value = operation.findtext("OperationID")
        try:
            return (1, float(value)) if value is not None else (0, 0)
        except ValueError:
            return (0, 0)

    def _project_user_sort_key(self, user: _Element) -> tuple[int, float, str]:
        display_order = user.findtext("Property[@name='DisplayOrder']")
        name = user.get("name", "")
        try:
            return (1, float(display_order), name)
        except (TypeError, ValueError):
            return (0, 0, name)

    def normalize_project_user(self, user_node: _Element) -> _Element:
        normalized = etree.Element("User")
        for name, value in user_node.attrib.items():
            normalized.set(name, value)

        for property_name in ("Authentication", "SecurityID", "Identity"):
            properties = user_node.xpath(f"Property[@name='{property_name}']")
            for prop in properties:
                if property_name != "Identity":
                    normalized.append(copy_node(prop))
                    continue

                identity_property = etree.Element("Property")
                for name, value in prop.attrib.items():
                    identity_property.set(name, value)
                identity_property.text = prop.text
                for identity in prop.xpath("Identity"):
                    identity_element = etree.SubElement(identity_property, "Identity")
                    if "name" in identity.attrib:
                        identity_element.set("name", identity.get("name"))
                    identity_element.text = identity.get("sid", "")
                    identity_element.tail = identity.tail
                normalized.append(identity_property)

        return normalized

    def normalize_operation(self, operation_node: _Element) -> _Element:
        normalized = etree.Element("Operation")
        normalized.set("operationId", operation_node.get("Guid", ""))
        normalized.set("name", operation_node.get("Name", ""))
        normalized.set("description", operation_node.get("Description", ""))

        operation_links = self.root.xpath(
            "//OperationLink[text() = $operation_id]",
            operation_id=operation_node.get("Guid", ""),
        )
        role_links = []
        for operation_link in operation_links:
            role = operation_link.getparent()
            if (
                role is not None
                and role.tag == "AzTask"
                and role.get("RoleDefinition") == "True"
                and role.get("Guid")
            ):
                role_links.append(role)

        if role_links:
            links = etree.SubElement(normalized, "Links")
            for role in role_links:
                links.append(self.add_role_link(role, {role.get("Guid", "")}))

        return normalized

    def add_role_link(
        self, role_node: _Element, visited_roles: set[str] | None = None
    ) -> _Element:
        if visited_roles is None:
            visited_roles = set()

        normalized = etree.Element("RoleLink")
        normalized.set("name", role_node.get("Name", ""))
        normalized.set("roleId", role_node.get("Guid", ""))

        role_id = role_node.get("Guid", "")
        for task_link in self.root.xpath(
            "//TaskLink[text() = $role_id]",
            role_id=role_id,
        ):
            parent_role = task_link.getparent()
            if (
                parent_role is None
                or parent_role.tag != "AzTask"
                or parent_role.get("RoleDefinition") != "True"
            ):
                continue
            parent_role_id = parent_role.get("Guid", "")
            if not parent_role_id or parent_role_id in visited_roles:
                continue
            normalized.append(
                self.add_role_link(parent_role, visited_roles | {parent_role_id})
            )

        return normalized

    def normalize_role(self, role_node: _Element) -> _Element:
        normalized = etree.Element("Role")

        task_link = role_node.findtext("TaskLink", default="")
        tasks = self.root.xpath("//AzTask[@Guid = $guid]", guid=task_link)
        task = tasks[0] if tasks else None
        normalized.set("roleId", task.get("Guid", "") if task is not None else "")
        normalized.set("name", task.get("Name", "") if task is not None else "")
        normalized.set("description", role_node.get("Description", ""))

        members = sorted(
            role_node.xpath("Member"), key=lambda member: member.text or ""
        )
        for member in members:
            normalized.append(self.normalize_member(member))

        return normalized

    def normalize_member(self, member_node: _Element) -> _Element:
        sid = member_node.xpath("string(.)")

        normalized = etree.Element("Member")
        normalized.set("sid", sid)

        if "S-1-5-" in sid:
            normalized.set("type", "windows")
        elif "S-1-9-" in sid:
            normalized.set("type", "ampla")
        else:
            normalized.set("type", "unknown")

        project_users = (
            self.project_security_root.xpath("./Users/User")
            if self.project_security_root is not None
            else []
        )
        matched_users, match_type = self._resolve_project_users(sid, project_users)
        if match_type == "identity":
            for user in matched_users:
                normalized.append(self.normalize_user_by_identity(user))
        elif match_type == "security_id":
            for user in matched_users:
                normalized.append(self.normalize_user_by_security_id(user))
        else:
            account_name = self.lookup_well_known_sid(sid)
            if account_name:
                account_user = etree.Element("User")
                account_user.set("name", sid)

                identity = etree.Element("Identity")
                identity.set("name", account_name)
                identity.text = sid
                account_user.append(identity)

                normalized.append(account_user)

            else:
                direct_user = etree.Element("User")
                direct_user.text = sid
                normalized.append(direct_user)

        return normalized

    def normalize_scope(self, scope_node: _Element) -> _Element:
        normalized = etree.Element("Scope")

        scope_id = (
            scope_node.get("Name") or scope_node.get("scopeId") or scope_node.get("id")
        )
        description = (
            scope_node.get("Description") or scope_node.get("description") or ""
        )

        if "Security scope for " in description:
            normalized.set("name", description.split("Security scope for ", 1)[1])
        else:
            normalized.set("name", description)

        normalized.set("scopeId", scope_id or "")
        project_scope_ids = (
            set(self.project_security_root.xpath("./Scopes/Scope/@scopeId"))
            if self.project_security_root is not None
            else set()
        )
        if scope_id in project_scope_ids:
            normalized.set("valid", "Scope is Valid")
        else:
            normalized.set("invalid", "Warning: Scope does not exist in Ampla Project.")

        for child in list(scope_node):
            if child.tag in {"AzRole", "Role"}:
                normalized.append(self.normalize_role(child))
            else:
                normalized.append(copy_node(child))

        return normalized

    def normalize_role_definition(self, task_node: _Element) -> _Element:
        normalized = etree.Element("RoleDefinition")
        normalized.set("roleId", task_node.get("Guid", ""))
        normalized.set("name", task_node.get("Name", ""))
        normalized.set("description", task_node.get("Description", ""))

        for child in list(task_node):
            if child.tag == "TaskLink":
                normalized.append(self.normalize_task_link(child))
        operation_links = sorted(
            task_node.xpath("OperationLink"), key=self._operation_link_sort_key
        )
        for operation_link in operation_links:
            normalized.append(self.normalize_operation_link(operation_link))

        return normalized

    def normalize_task_link(self, task_link_node: _Element) -> _Element:
        target_guid = task_link_node.text or ""
        normalized = etree.Element("RoleLink")
        tasks = self.root.xpath("//AzTask[@Guid = $guid]", guid=target_guid)
        role_node = tasks[0] if tasks else None
        normalized.set(
            "name", role_node.get("Name", "") if role_node is not None else ""
        )
        normalized.set(
            "roleId", role_node.get("Guid", "") if role_node is not None else ""
        )

        if role_node is not None:
            for operation_link in sorted(
                role_node.xpath("OperationLink"), key=self._operation_link_sort_key
            ):
                normalized.append(self.normalize_operation_link(operation_link))

        return normalized

    def _operation_link_sort_key(self, operation_link: _Element) -> tuple[int, float]:
        operation_id = operation_link.text or ""
        operations = self.root.xpath("//AzOperation[@Guid = $guid]", guid=operation_id)
        value = operations[0].findtext("OperationID") if operations else None
        try:
            return (1, float(value)) if value is not None else (0, 0)
        except ValueError:
            return (0, 0)

    def normalize_operation_link(self, operation_link_node: _Element) -> _Element:
        operation_id = operation_link_node.text or ""
        normalized = etree.Element("Operation")
        operations = self.root.xpath("//AzOperation[@Guid = $guid]", guid=operation_id)
        normalized.set("name", operations[0].get("Name", "") if operations else "")

        return normalized

    def resolve_user(self, sid: str, project_users: Any) -> _Element | None:
        matched_users, _ = self._resolve_project_users(sid, project_users)
        return matched_users[0] if matched_users else None

    def _resolve_project_users(
        self, sid: str, project_users: Any
    ) -> tuple[list[_Element], str | None]:
        if project_users is None:
            project_users = []
        if isinstance(project_users, dict):
            project_users = list(project_users.values())
        else:
            project_users = list(project_users)

        identity_users = self._find_users_by_identity(sid, project_users)
        if identity_users:
            return identity_users, "identity"
        security_id_users = self._find_users_by_security_id(sid, project_users)
        if security_id_users:
            return security_id_users, "security_id"
        return [], None

    def _find_users_by_identity(self, sid: str, project_users: Any) -> list[_Element]:
        return [
            user
            for user in project_users
            if user is not None
            and user.xpath("Property[@name='Identity']/Identity[@sid=$sid]", sid=sid)
        ]

    def _find_users_by_security_id(
        self, sid: str, project_users: Any
    ) -> list[_Element]:
        return [
            user
            for user in project_users
            if user is not None
            and user.xpath(
                "Property[@name='SecurityID']/text() = $sid",
                sid=sid,
            )
        ]

    def lookup_well_known_sid(self, sid: str) -> str:
        well_known = {
            "S-1-5-32-544": r".\Administrators",
            "S-1-5-32-545": r".\Users",
            "S-1-5-32-546": r".\Guests",
            "S-1-5-32-547": r".\Power Users",
            "S-1-5-11": "Authenticated Users",
        }

        if sid in well_known:
            return well_known[sid]

        return ""

    def normalize_user(self, user_node: _Element) -> _Element:
        normalized = etree.Element("User")

        for name, value in user_node.attrib.items():
            normalized.set(name, value)

        for property_name in ("Authentication", "SecurityID", "Identity"):
            properties = user_node.xpath(f"Property[@name='{property_name}']")
            for prop in properties:
                if property_name == "Identity":
                    normalized_property = etree.Element("Property")
                    for name, value in prop.attrib.items():
                        normalized_property.set(name, value)
                    normalized_property.text = prop.text
                    for child in list(prop):
                        if child.tag == "Identity":
                            normalized_child = self.normalize_identity(child)
                            normalized_child.tail = child.tail
                        else:
                            normalized_child = copy_node(child)
                        normalized_property.append(normalized_child)
                else:
                    normalized_property = self.normalize_named_property(prop)
                normalized.append(normalized_property)

        return normalized

    def normalize_user_by_identity(self, user_node: _Element) -> _Element:
        normalized = etree.Element("User")

        for attr in ["name", "id", "hash"]:
            if attr in user_node.attrib:
                normalized.set(attr, user_node.get(attr))

        for identity in user_node.xpath("Property[@name='Identity']/Identity"):
            normalized.append(self.normalize_identity(identity))

        return normalized

    def normalize_user_by_security_id(self, user_node: _Element) -> _Element:
        normalized = etree.Element("User")

        for attr in ["name", "id", "hash"]:
            if attr in user_node.attrib:
                normalized.set(attr, user_node.get(attr))

        security_id = user_node.find("Property[@name='SecurityID']")
        if security_id is not None:
            normalized.text = security_id.xpath("string(.)")

        return normalized

    def normalize_identity(self, identity_node: _Element) -> _Element:
        normalized = etree.Element("Identity")

        if "name" in identity_node.attrib:
            normalized.set("name", identity_node.get("name"))

        normalized.text = identity_node.get("sid", "")

        return normalized

    def normalize_named_property(self, property_node: _Element) -> _Element:
        return copy_node(property_node)

    def copy_attribute(self, attr: Any) -> Any:
        return attr
