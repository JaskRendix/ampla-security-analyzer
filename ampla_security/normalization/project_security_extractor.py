"""
Project Security Extraction - transforms normalized project to security elements.

This implements the Project.Security.xslt transformation, extracting
Users and Scopes from the normalized project for use by AuthStore normalization.
"""

from lxml import etree
from lxml.etree import _Element, _ElementTree


class ProjectSecurityExtractor:
    """Extracts security-relevant data from normalized project."""

    def __init__(self, normalized_project_tree: _ElementTree):
        self.tree: _ElementTree = normalized_project_tree
        self.root: _Element = normalized_project_tree.getroot()

    def extract(self) -> _ElementTree:
        """Extract security information from normalized project."""
        security = etree.Element("Security")

        # Extract Users
        users_elem = etree.SubElement(security, "Users")
        for user_item in self.root.xpath(
            "//Item[@type='Citect.Ampla.StandardItems.User']"
        ):
            user_elem = self._extract_user(user_item)
            if user_elem is not None:
                users_elem.append(user_elem)

        # Extract Scopes
        scopes_elem = etree.SubElement(security, "Scopes")

        # Always add global scope
        global_scope = etree.SubElement(scopes_elem, "Scope")
        global_scope.set("scopeId", "00000000-0000-0000-0000-000000000000")
        global_scope.set("name", "{Global}")
        global_scope.set("fullName", "{Global}")

        # Add items with InheritPermissions=False as scopes
        for item in self.root.xpath(
            "//Item[Property[@name='InheritPermissions' and text()='False']]"
        ):
            scope_elem = etree.SubElement(scopes_elem, "Scope")
            scope_elem.set("scopeId", item.get("id", ""))
            scope_elem.set("name", item.get("name", ""))
            scope_elem.set("fullName", item.get("fullName", ""))
            scope_elem.set("id", item.get("id", ""))

        return etree.ElementTree(security)

    def _extract_user(self, user_item: _Element) -> _Element:
        """Extract a User element from a User item."""
        user = etree.Element("User")

        # Copy attributes
        for attr in ["id", "name", "hash", "fullName", "type"]:
            value = user_item.get(attr)
            if value:
                user.set(attr, value)

        # Copy DisplayOrder property
        display_order = user_item.xpath("Property[@name='DisplayOrder']")
        if display_order:
            user.append(self._copy_property(display_order[0]))

        # Copy Authentication property
        auth = user_item.xpath("Property[@name='Authentication']")
        if auth:
            user.append(self._copy_property(auth[0]))

        # Copy Identity property (parse SID)
        identity = user_item.xpath("Property[@name='Identity']")
        if identity:
            user.append(self._parse_identity_property(identity[0]))

        # Copy SecurityID property
        security_id = user_item.xpath("Property[@name='SecurityID']")
        if security_id:
            user.append(self._copy_property(security_id[0]))

        return user

    def _copy_property(self, prop: _Element) -> _Element:
        """Copy a property element."""
        new_prop = etree.Element(prop.tag)

        for attr in prop.attrib:
            new_prop.set(attr, prop.get(attr))

        new_prop.text = prop.text

        for child in prop:
            new_prop.append(etree.fromstring(etree.tostring(child)))

        return new_prop

    def _parse_identity_property(self, identity_prop: _Element) -> _Element:
        """Parse Identity property and extract name and SID."""
        new_prop = etree.Element("Property")
        new_prop.set("name", identity_prop.get("name", "Identity"))

        value = (identity_prop.text or "").strip()
        if not value:
            return new_prop

        # Parse pipe-separated format: account|sid|other
        parts = value.split("|")
        account = parts[0].strip() if len(parts) > 0 else ""
        sid = parts[1].strip() if len(parts) > 1 else ""

        # Create Identity sub-element
        identity_elem = etree.SubElement(new_prop, "Identity")
        if account:
            identity_elem.set("name", account)
        if sid:
            identity_elem.set("sid", sid)
        identity_elem.text = value

        return new_prop
