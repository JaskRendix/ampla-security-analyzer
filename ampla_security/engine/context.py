from __future__ import annotations

from lxml.etree import _Element, _ElementTree

from ampla_security.xml.xpath import find_nodes


class AnalysisContext:
    """
    Holds normalized XML and derived indexes for rule evaluation.
    """

    def __init__(self, xml_tree: _ElementTree):
        self.tree: _ElementTree = xml_tree
        self.root: _Element = xml_tree.getroot()

        self.items: dict[str, _Element] = self._index_items()
        self.scopes: dict[str, _Element] = self._index_scopes()
        self.users: dict[str, _Element] = self._index_users()
        self.roles: dict[str, _Element] = self._index_roles()

    def _index_items(self) -> dict[str, _Element]:
        return {
            item.get("id"): item
            for item in find_nodes(self.root, "//Item[@id]")
            if item.get("id")
        }

    def _index_scopes(self) -> dict[str, _Element]:
        scopes: dict[str, _Element] = {}

        for scope in find_nodes(
            self.root,
            (
                "//AzScope[@id] | "
                "//Scope[@id] | "
                "//Item[@id][Property[@name='InheritPermissions' "
                "and normalize-space(text())='False']]"
            ),
        ):
            scope_id = scope.get("id") or scope.get("scopeId")
            if scope_id:
                scopes[scope_id] = scope

        return scopes

    def _index_users(self) -> dict[str, _Element]:
        users: dict[str, _Element] = {}

        for user in find_nodes(self.root, "//User[@sid] | //User[@id]"):
            key = user.get("sid") or user.get("id")
            if key:
                users[key] = user

        return users

    def _index_roles(self) -> dict[str, _Element]:
        roles: dict[str, _Element] = {}

        for role in find_nodes(self.root, "//Role | //RoleDefinition"):
            key = role.get("roleId") or role.get("name")
            if key:
                roles[key] = role

        return roles

    def find(self, xpath: str) -> list[_Element]:
        return find_nodes(self.root, xpath)

    def get_item(self, item_id: str | None) -> _Element | None:
        return self.items.get(item_id) if item_id else None

    def get_scope(self, scope_id: str | None) -> _Element | None:
        return self.scopes.get(scope_id) if scope_id else None

    def get_user(self, sid: str | None) -> _Element | None:
        return self.users.get(sid) if sid else None

    def get_role(self, role_id: str | None) -> _Element | None:
        return self.roles.get(role_id) if role_id else None
