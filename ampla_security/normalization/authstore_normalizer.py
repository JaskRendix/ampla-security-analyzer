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
        self.users_by_sid: dict[str, _Element] = {}
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
        self._index_users()

        normalized_root = self.normalize_authstore_root(self.root)
        return etree.ElementTree(normalized_root)

    def _index_users(self) -> None:
        for user in self.root.xpath("//User[@sid]"):
            sid = user.get("sid")
            if sid:
                self.users_by_sid[sid] = user

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

        users = etree.SubElement(normalized, "Users")
        if self.project_security_root is not None:
            project_users = self.project_security_root.xpath("./Users/User")
            for user in sorted(project_users, key=self._project_user_sort_key):
                users.append(self.normalize_project_user(user))

        return normalized

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
                    if identity.get("name"):
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

        return normalized

    def add_role_link(self, role_node: _Element, visited_roles: Any) -> _Element:
        normalized = etree.Element("RoleLink")

        if role_node.get("Name"):
            normalized.set("name", role_node.get("Name"))
        if role_node.get("Guid"):
            normalized.set("roleId", role_node.get("Guid"))

        for task_link in role_node.xpath("TaskLink"):
            normalized.append(self.normalize_task_link(task_link))

        return normalized

    def normalize_role(self, role_node: _Element) -> _Element:
        normalized = etree.Element("Role")

        role_id = role_node.get("Guid") or role_node.get("roleId")
        if role_id:
            normalized.set("roleId", role_id)

        name = role_node.get("Name") or role_node.get("name")
        if name:
            normalized.set("name", name)

        desc = role_node.get("Description") or role_node.get("description")
        if desc:
            normalized.set("description", desc)

        for child in list(role_node):
            if child.tag == "Member":
                normalized.append(self.normalize_member(child))
            else:
                normalized.append(copy_node(child))

        return normalized

    def normalize_member(self, member_node: _Element) -> _Element:
        sid = (member_node.text or "").strip()

        normalized = etree.Element("Member")
        normalized.set("sid", sid)

        if sid.startswith("S-1-5-"):
            normalized.set("type", "windows")
        elif sid.startswith("S-1-9-"):
            normalized.set("type", "ampla")
        else:
            normalized.set("type", "unknown")

        user = self.resolve_user(sid, self.users_by_sid)

        if user is not None:
            normalized.append(self.normalize_user(user))

        else:
            account_name = self.lookup_well_known_sid(sid)
            if account_name:
                account_user = etree.Element("User")
                account_user.set("sid", sid)
                account_user.set("name", account_name)

                identity = etree.Element("Identity")
                identity.set("name", account_name)
                identity.text = sid
                account_user.append(identity)

                normalized.append(account_user)

            else:
                direct_user = etree.Element("User")
                direct_user.set("sid", sid)
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
            elif child.tag == "OperationLink":
                normalized.append(self.normalize_operation_link(child))
            else:
                normalized.append(copy_node(child))

        return normalized

    def normalize_task_link(self, task_link_node: _Element) -> _Element:
        target_guid = (task_link_node.text or "").strip()
        normalized = etree.Element("RoleLink")

        role_node = self.root.xpath(f"//AzTask[@Guid='{target_guid}']")
        if role_node:
            role_node = role_node[0]

            if role_node.get("Name"):
                normalized.set("name", role_node.get("Name"))
            if role_node.get("Guid"):
                normalized.set("roleId", role_node.get("Guid"))

            for child in role_node.xpath("OperationLink"):
                normalized.append(self.normalize_operation_link(child))

        return normalized

    def normalize_operation_link(self, operation_link_node: _Element) -> _Element:
        operation_id = (operation_link_node.text or "").strip()
        normalized = etree.Element("Operation")

        operation_node = self.root.xpath(f"//AzOperation[@Guid='{operation_id}']")
        if operation_node:
            operation_node = operation_node[0]
            if operation_node.get("Name"):
                normalized.set("name", operation_node.get("Name"))

        return normalized

    def resolve_user(self, sid: str, project_users: Any) -> _Element | None:
        if project_users is None:
            project_users = []

        if isinstance(project_users, dict):
            user = project_users.get(sid)
            if user is not None:
                return user
            project_users = list(project_users.values())

        for user in project_users:
            if user is None:
                continue

            if user.get("sid") == sid:
                return user

            security_prop = user.find("Property[@name='SecurityID']")
            if security_prop is not None and (security_prop.text or "").strip() == sid:
                return user

            identity = user.find("Property[@name='Identity']/Identity")
            if identity is not None and identity.get("sid") == sid:
                return user

        return self.users_by_sid.get(sid)

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

        if sid.startswith("S-1-5-21-"):
            parts = sid.split("-")
            if len(parts) >= 4:
                last3 = parts[-1]
                domain = "-".join(parts[3:-1])

                account_map = {
                    "500": "Administrator",
                    "512": "Domain Administrators",
                    "513": "Domain Users",
                }

                account = account_map.get(last3)
                if account:
                    return f"({domain})/{account}"

        return ""

    def normalize_user(self, user_node: _Element) -> _Element:
        normalized = etree.Element("User")

        for name, value in user_node.attrib.items():
            normalized.set(name, value)

        for prop in user_node.xpath(
            "Property[@name='Authentication' or @name='SecurityID']"
        ):
            normalized.append(self.normalize_named_property(prop))

        identity_prop = user_node.find("Property[@name='Identity']/Identity")
        if identity_prop is not None:
            normalized.append(self.normalize_identity(identity_prop))

        if user_node.get("sid"):
            normalized.set("sid", user_node.get("sid"))
            normalized.set("identifier", user_node.get("sid"))

        return normalized

    def normalize_user_by_identity(self, user_node: _Element) -> _Element:
        normalized = etree.Element("User")

        for attr in ["name", "id", "hash"]:
            if user_node.get(attr):
                normalized.set(attr, user_node.get(attr))

        identity = user_node.find("Property[@name='Identity']/Identity")
        if identity is not None:
            normalized.append(self.normalize_identity(identity))

        return normalized

    def normalize_user_by_security_id(self, user_node: _Element) -> _Element:
        normalized = etree.Element("User")

        for attr in ["name", "id", "hash"]:
            if user_node.get(attr):
                normalized.set(attr, user_node.get(attr))

        security_id = user_node.find("Property[@name='SecurityID']")
        if security_id is not None and security_id.text:
            normalized.text = security_id.text.strip()

        return normalized

    def normalize_identity(self, identity_node: _Element) -> _Element:
        normalized = etree.Element("Identity")

        for name, value in identity_node.attrib.items():
            normalized.set(name, value)

        normalized.text = identity_node.get("sid") or (identity_node.text or "").strip()

        return normalized

    def normalize_named_property(self, property_node: _Element) -> _Element:
        return copy_node(property_node)

    def copy_attribute(self, attr: Any) -> Any:
        return attr
