"""
Project Security Extraction - transforms normalized project to security elements.

This implements the Project.Security.xslt transformation, extracting
Users and Scopes from the normalized project for use by AuthStore normalization.
"""

import copy
import math
import re

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
        user_items = self.root.xpath("//Item[@type='Citect.Ampla.StandardItems.User']")
        for user_item in self._sort_xslt_items(user_items):
            users_elem.append(self._extract_user(user_item))

        # Extract Scopes
        scopes_elem = etree.SubElement(security, "Scopes")

        # Always add global scope
        global_scope = etree.SubElement(scopes_elem, "Scope")
        global_scope.set("scopeId", "00000000-0000-0000-0000-000000000000")
        global_scope.set("name", "{Global}")
        global_scope.set("fullName", "{Global}")

        # Add items with InheritPermissions=False as scopes
        scope_items = self.root.xpath(
            "//Item[Property[@name='InheritPermissions']/text()='False']"
        )
        for item in self._sort_xslt_items(scope_items):
            scope_elem = etree.SubElement(scopes_elem, "Scope")
            scope_elem.set("scopeId", item.get("id", ""))
            for name, value in item.attrib.items():
                scope_elem.set(name, value)

        return etree.ElementTree(security)

    def _sort_xslt_items(self, items: list[_Element]) -> list[_Element]:
        def sort_key(item: _Element) -> tuple[str, int, float, str]:
            parent = item.getparent()
            parent_full_name = parent.get("fullName", "") if parent is not None else ""
            display_orders = item.xpath("Property[@name='DisplayOrder']")
            display_order = (
                self._xpath_number(display_orders[0]) if display_orders else math.nan
            )
            is_nan = math.isnan(display_order)
            return (
                parent_full_name,
                0 if is_nan else 1,
                0.0 if is_nan else display_order,
                item.get("name", ""),
            )

        return sorted(items, key=sort_key)

    def _xpath_number(self, node: _Element) -> float:
        value = "".join(node.itertext()).strip()
        if not re.fullmatch(r"-?(?:\d+(?:\.\d*)?|\.\d+)", value):
            return math.nan
        return float(value)

    def _extract_user(self, user_item: _Element) -> _Element:
        """Extract a User element from a User item."""
        user = etree.Element("User")

        for name, value in user_item.attrib.items():
            user.set(name, value)

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
        return copy.deepcopy(prop)

    def _parse_identity_property(self, identity_prop: _Element) -> _Element:
        """Parse Identity property and extract name and SID."""
        new_prop = etree.Element(identity_prop.tag)
        for name, value in identity_prop.attrib.items():
            new_prop.set(name, value)

        value = "".join(identity_prop.itertext())
        parts = value.split("|")
        account = parts[0] if len(parts) > 1 else ""
        sid = parts[1] if len(parts) > 2 else ""

        identity_elem = etree.SubElement(new_prop, "Identity")
        if account:
            identity_elem.set("name", account)
        if sid:
            identity_elem.set("sid", sid)
        if value:
            identity_elem.text = value

        return new_prop
