from lxml import etree

from ampla_security.utils.hashing import sha1
from ampla_security.xml.utils import copy_node

FAVORITE_DESCRIPTOR_TYPE = (
    "Citect.Ampla.General.Common.FavoriteDescriptor," "Citect.Ampla.General.Common"
)
FAVORITE_COLLECTION_TYPE = (
    "Citect.Ampla.General.Common.FavoriteDescriptorCollection,"
    "Citect.Ampla.General.Common"
)


class ProjectNormalizer:
    """
    Orchestrates normalization of Ampla project XML.
    """

    def __init__(self, xml_tree: etree._ElementTree):
        self.tree = xml_tree
        self.root = xml_tree.getroot()
        self.items_by_id = {}
        self.references_by_id = {}

    def normalize(self) -> etree._ElementTree:
        self._index_items()
        self._index_references()

        if self.root.tag == "Ampla":
            normalized_root = self.normalize_project_ampla(self.root)
        elif self.root.tag == "CitectIIM":
            normalized_root = self.normalize_project_citect_iim(self.root)
        else:
            normalized_root = self.normalize_document(self.root)

        self._finalize_items(normalized_root)
        return etree.ElementTree(normalized_root)

    def _index_items(self) -> None:
        for item in self.root.xpath("//Item[@id]"):
            self.items_by_id[item.get("id")] = item

    def _index_references(self) -> None:
        for ref in self.root.xpath("//Reference[@id]"):
            self.references_by_id[ref.get("id")] = ref

    def _finalize_items(self, root: etree._Element) -> None:
        for item in root.xpath("//Item[@id]"):
            self.add_item_attributes(item)

    def normalize_document(self, root):
        normalized = copy_node(root)
        self._normalize_item_children(normalized)
        return normalized

    def normalize_project_ampla(self, ampla_root):
        project = etree.Element("Project")
        properties = etree.SubElement(project, "Properties")

        platform_version = ampla_root.xpath(
            "Reference[@name='Citect.Ampla.StandardItems']/@version"
        )
        applications_version = ampla_root.xpath(
            "Reference[@name='Citect.Ampla.General.Server']/@version"
        )

        project_version = etree.SubElement(properties, "ProjectProperty")
        project_version.set("name", "Platform.Version")
        project_version.text = platform_version[0] if platform_version else ""

        apps_version = etree.SubElement(properties, "ProjectProperty")
        apps_version.set("name", "Applications.Version")
        apps_version.text = applications_version[0] if applications_version else ""

        for name, value in ampla_root.attrib.items():
            properties.append(self.normalize_project_attribute(name, value))

        for reference in ampla_root.xpath("Reference[Type]"):
            normalized_reference = self.normalize_reference(reference)
            if normalized_reference is not None:
                project.append(normalized_reference)

        for class_def in ampla_root.xpath("ClassDefinitions/ClassDefinition"):
            project.append(self.normalize_class_definition(class_def))

        for item in ampla_root.xpath("Item"):
            project.append(self.normalize_item(item))

        return project

    def normalize_project_citect_iim(self, citect_root):
        project = etree.Element("Project")
        properties = etree.SubElement(project, "Properties")

        platform_version = citect_root.xpath(
            "Reference[@name='Citect.Ampla.StandardItems']/@version"
        )
        applications_version = citect_root.xpath(
            "Reference[@name='Citect.Ampla.General.Server']/@version"
        )

        project_version = etree.SubElement(properties, "ProjectProperty")
        project_version.set("name", "Platform.Version")
        project_version.text = platform_version[0] if platform_version else ""

        apps_version = etree.SubElement(properties, "ProjectProperty")
        apps_version.set("name", "Applications.Version")
        apps_version.text = applications_version[0] if applications_version else ""

        for name, value in citect_root.attrib.items():
            properties.append(self.normalize_project_attribute(name, value))

        for reference in citect_root.xpath("Reference[Type]"):
            normalized_reference = self.normalize_reference(reference)
            if normalized_reference is not None:
                project.append(normalized_reference)

        for class_def in citect_root.xpath("ClassDefinitions/ClassDefinition"):
            project.append(self.normalize_class_definition(class_def))

        for item in citect_root.xpath("Item"):
            project.append(self.normalize_item(item))

        return project

    def normalize_project_attribute(self, name, value):
        project_property = etree.Element("ProjectProperty")
        project_property.set("name", name)
        project_property.text = value
        return project_property

    def normalize_reference(self, reference):
        reference_name = reference.get("name")
        if not reference_name:
            return None

        item_matches = self.root.xpath(f"//Item[@reference='{reference_name}']")
        if not item_matches:
            return None

        normalized = etree.Element("Reference")
        normalized.set("name", reference_name)

        reference_prefix = f"{reference_name}."
        for type_node in reference.xpath("Type"):
            normalized_type = self.normalize_type(type_node, reference_prefix)
            if normalized_type is not None:
                normalized.append(normalized_type)

        if len(normalized) == 0:
            return None

        return normalized

    def normalize_type(self, type_node, reference_prefix):
        type_name = type_node.get("name")
        if not type_name:
            return None

        matching_items = self.root.xpath(f"//Item[@type='{type_name}']")
        if not matching_items:
            return None

        normalized = etree.Element("Type")
        full_name = type_name
        if reference_prefix and type_name.startswith(reference_prefix):
            normalized.set("name", type_name[len(reference_prefix) :])
        else:
            normalized.set("name", type_name)
        normalized.set("fullName", full_name)
        normalized.set("referencePrefix", reference_prefix)
        return normalized

    def normalize_class_definition(self, class_def):
        item = etree.Element("Item")
        item.set("hash", class_def.get("id") or "")
        if class_def.get("id"):
            item.set("id", class_def.get("id"))
        if class_def.get("name"):
            item.set("name", class_def.get("name"))
        if class_def.get("type"):
            item.set("type", class_def.get("type"))
        item.set("class", "true")
        item.set("fullName", self.get_class_full_name_by_id(class_def.get("id")))
        self.add_translation(item)

        ancestors = class_def.xpath("ancestor::ClassDefinition")
        if len(ancestors) > 1:
            inherits_prop = etree.Element("Property")
            inherits_prop.set("name", "(inherits)")
            for ancestor in ancestors:
                if ancestor is class_def:
                    continue
                item_link = etree.Element("ItemLink")
                if ancestor.get("id"):
                    item_link.set("targetID", ancestor.get("id"))
                absolute_path = self.get_class_full_name_by_id(ancestor.get("id"))
                if absolute_path:
                    item_link.set("absolutePath", absolute_path)
                inherits_prop.append(item_link)
            if len(inherits_prop):
                item.append(inherits_prop)

        for prop_def in class_def.xpath(
            "ancestor-or-self::ClassDefinition/PropertyDefinition"
        ):
            prop = etree.Element("Property")
            for name, value in prop_def.attrib.items():
                prop.set(name, value)
            prop.text = prop_def.text
            item.append(prop)

        for child_class in class_def.xpath("ClassDefinition"):
            normalized_child = self.normalize_class_definition(child_class)
            if normalized_child is not None:
                item.append(normalized_child)

        return item

    def add_translation(self, target):
        return target

    def normalize_item(self, item_node):
        if "id" not in item_node.attrib:
            item = copy_node(item_node)
            for child in list(item):
                if child.tag == "Property":
                    normalized_property = self.normalize_item_property(child, item)
                    if normalized_property is None:
                        item.remove(child)
                    else:
                        item.replace(child, normalized_property)
                elif child.tag == "Item":
                    normalized_item = self.normalize_item(child)
                    normalized_item.tail = child.tail
                    item.replace(child, normalized_item)
                elif (
                    child.tag == "ItemClassAssociation"
                    and "classDefinitionId" in child.attrib
                ):
                    normalized_association = self.normalize_item_class_association(
                        child
                    )
                    normalized_association.tail = child.tail
                    item.replace(child, normalized_association)
                else:
                    self._normalize_item_children(child, item)
            return item

        item = etree.Element("Item")
        for attribute in ("id", "name", "type"):
            if attribute in item_node.attrib:
                item.set(attribute, item_node.get(attribute))
        item.set("fullName", self.get_item_full_name(item_node))
        self.add_translation(item)

        for child in item_node:
            if child.tag == "ItemClassAssociation":
                if "classDefinitionId" in child.attrib:
                    item.append(self.normalize_item_class_association(child))
                else:
                    copied_association = copy_node(child)
                    copied_association.tail = None
                    item.append(copied_association)
        for child in item_node:
            if child.tag == "Property":
                normalized_property = self.normalize_item_property(child, item_node)
                if normalized_property is not None:
                    normalized_property.tail = None
                    item.append(normalized_property)

        if item.get("type") not in (
            "Citect.Ampla.General.Server.DecisionMatrix",
            "Citect.Ampla.General.Server.DecisionMatrixRule",
        ):
            self.add_property_display_order(item)
        for child in item_node:
            if child.tag == "Item":
                item.append(self.normalize_item(child))

        # Apply specialized item transforms
        item_type = item.get("type")
        if item_type == "Citect.Ampla.StandardItems.User":
            item = self.normalize_user_item(item)
        elif item_type == "Citect.Ampla.Metrics.Server.Resolvers.Resolver":
            item = self.normalize_resolver_item(item)
        elif item_type == "Citect.Ampla.General.Server.DecisionMatrix":
            item = self.normalize_decision_matrix(item)
        elif item_type == "Citect.Ampla.General.Server.DecisionMatrixRule":
            item = self.normalize_decision_matrix_rule(item_node, item)

        return item

    def normalize_decision_matrix(self, item):
        inputs = []
        for source_input in item.xpath(
            "Item[@type='Citect.Ampla.StandardItems.CalculatedVariable']"
        ):
            input_node = etree.Element("Input")
            item_id = source_input.get("id")
            item_name = source_input.get("name")
            input_node.set(
                "hash",
                sha1(
                    item_id
                    or "|".join(
                        [
                            item_name or "",
                            source_input.get("type", ""),
                            source_input.get("class", ""),
                        ]
                    )
                ),
            )
            if item_id is not None:
                input_node.set("id", item_id)
            if item_name is not None:
                input_node.set("name", item_name)
            self.add_translation(input_node)
            input_node.set(
                "displayOrder",
                self._item_display_order(source_input),
            )
            input_node.append(self._decision_matrix_item_link(source_input))
            inputs.append(input_node)

        return self._order_decision_matrix_children(item, inputs)

    def normalize_decision_matrix_rule(self, source_item, item):
        inputs = []
        parent = source_item.getparent()
        if parent is not None:
            for source_input in parent.xpath(
                "Item[@type='Citect.Ampla.StandardItems.CalculatedVariable']"
            ):
                input_name = source_input.get("name", "")
                input_rule = etree.Element("InputRule")
                input_rule.set("name", input_name)
                input_rule.set(
                    "displayOrder",
                    self._item_display_order(source_input),
                )
                values = source_item.xpath("Property[@name=$name]", name=input_name)
                input_rule.set(
                    "value",
                    "".join(values[0].itertext()) if values else "Ignore",
                )
                input_rule.append(self._decision_matrix_item_link(source_input))
                inputs.append(input_rule)

        return self._order_decision_matrix_children(item, inputs)

    def _item_display_order(self, item):
        values = item.xpath("Property[@name='DisplayOrder']")
        if values:
            return "".join(values[0].itertext())
        return self._get_default_display_order()

    def _decision_matrix_item_link(self, item):
        link = etree.Element("ItemLink")
        link.set("targetID", item.get("id", ""))
        link.set("absolutePath", self.get_item_full_name(item))
        return link

    def _order_decision_matrix_children(self, item, generated):
        properties = [child for child in item if child.tag == "Property"]
        items = [child for child in item if child.tag == "Item"]

        item[:] = []
        for child in generated:
            item.append(child)

        if not any(prop.get("name") == "DisplayOrder" for prop in properties):
            display_order = etree.Element("Property")
            display_order.set("name", "DisplayOrder")
            display_order.text = self._get_default_display_order()
            properties.insert(0, display_order)

        for child in properties:
            item.append(child)
        for child in items:
            item.append(child)
        return item

    def normalize_item_property(self, property_node, parent_item=None):
        if (
            parent_item is not None
            and "id" in parent_item.attrib
            and self.exclude_definition_property(property_node)
        ):
            return None

        prop_name = property_node.get("name")

        # Apply specialized property transforms
        parent_type = parent_item.get("type") if parent_item is not None else None

        if self._has_soap_envelope(property_node):
            if parent_type == "Citect.Ampla.Connectors.OleDbConnector.OleDbAdapter":
                return self.normalize_oledb_soap_property(property_node)
            return self.normalize_soap_property(property_node)
        if prop_name == "EquipmentTypes":
            return self.normalize_equipment_types_property(property_node)
        if prop_name and "Subscription" in prop_name:
            return self.normalize_subscriptions_property(property_node, parent_item)

        if (
            parent_type == "Citect.Ampla.General.Server.RecordStates.CycleManager"
            and prop_name == "Cycles"
        ):
            normalized = self.normalize_cycle_manager_cycles(property_node)

        # Hook: Home property
        elif prop_name == "Home":
            normalized = self.normalize_home_property(property_node)

        # Hook: Favorites property
        elif prop_name == "Favorites":
            normalized = self.normalize_favorites_property(property_node)

        # Equipment template target class reference
        elif (
            parent_item is not None
            and parent_type
            == "Citect.Ampla.General.Server.Templating.EquipmentTemplate"
            and prop_name == "TargetEquipmentClass"
        ):
            normalized = self.normalize_equipment_template_target(property_node)
        else:
            normalized = copy_node(property_node)
            if parent_item is not None and "id" in parent_item.attrib:
                for attribute in list(normalized.attrib):
                    if attribute not in ("id", "name"):
                        del normalized.attrib[attribute]

        self._normalize_item_children(normalized, parent_item)
        return normalized

    def _has_soap_envelope(self, property_node):
        return bool(
            property_node.xpath(
                "./*[local-name()='Envelope' and "
                "namespace-uri()='http://schemas.xmlsoap.org/soap/envelope/']"
            )
        )

    def normalize_soap_property(self, property_node):
        normalized = etree.Element("Property")
        if property_node.get("name") is not None:
            normalized.set("name", property_node.get("name"))
        normalized.set("isSoap", "true")
        normalized.text = "{SOAP}"
        return normalized

    def normalize_oledb_soap_property(self, property_node):
        normalized = self.normalize_soap_property(property_node)
        normalized.text = None
        values = property_node.xpath(
            ".//*[namespace-uri()='' and string-length(.) > 0]"
        )
        if not values:
            normalized.text = "{SOAP}"
            return normalized

        for value in values:
            soap_property = etree.SubElement(normalized, "soap-property")
            soap_property.set("name", etree.QName(value).localname)
            soap_property.text = value.xpath("string(.)")
        return normalized

    def normalize_equipment_types_property(self, property_node):
        normalized = etree.Element(property_node.tag)
        for name, value in property_node.attrib.items():
            normalized.set(name, value)
        value = property_node.xpath("string(.)")
        for path in self._csv_values(value):
            item_link = etree.SubElement(normalized, "ItemLink")
            item_link.set("absolutePath", path)
        return normalized

    def _csv_values(self, value):
        if "," not in value:
            return [value]
        first, rest = value.split(",", 1)
        return [first, *self._csv_values(rest)]

    def normalize_subscriptions_property(self, property_node, parent_item=None):
        normalized = etree.Element(property_node.tag)
        for name, value in property_node.attrib.items():
            normalized.set(name, value)

        value = property_node.xpath("string(.)")
        if "|" not in value:
            normalized = copy_node(property_node)
            self._normalize_item_children(normalized, parent_item)
            return normalized

        text = etree.SubElement(normalized, "text")
        text.text = property_node.text
        for child in property_node:
            text.append(copy_node(child))
        self._normalize_item_children(text, parent_item)
        lines = self._split_subscription_lines(value)
        for line in lines:
            self._append_subscription(normalized, line)
        return normalized

    def _split_subscription_lines(self, value):
        if "\r\n" in value:
            line, remainder = value.split("\r\n", 1)
            return [line, *self._split_subscription_lines(remainder)]
        if "\r" in value:
            line, remainder = value.split("\r", 1)
            return [line, *self._split_subscription_lines(remainder)]
        return [value]

    def _append_subscription(self, parent, line):
        if not line:
            return

        if "|" not in line:
            parent.append(self._subscription_comment(0, line))
            return

        item_link = etree.SubElement(parent, "ItemLink")
        type_name, remainder = line.split("|", 1)
        item_link.set("type", type_name)
        fields = remainder.split("|")
        if len(fields) < 2:
            item_link.append(self._subscription_comment(1, remainder))
            return
        item_link.set("absolutePath", fields[0])

        if len(fields) < 3:
            item_link.append(self._subscription_comment(2, fields[1]))
            return
        item_link.set("event", fields[1])

        if len(fields) < 4:
            item_link.set("handler", fields[2])
            return
        item_link.set("handler", fields[2])

        if len(fields) == 4:
            item_link.set("expressionMatch", fields[3])
        else:
            item_link.append(self._subscription_comment(4, "|".join(fields[3:])))

    def _subscription_comment(self, index, line):
        prefix = "" if index == 0 else "\n                "
        return etree.Comment(f"{prefix}Unexpected Subscription [{index}]: {line}")

    def _normalize_item_children(self, parent_node, parent_item=None):
        for child in list(parent_node):
            if child.tag == "Property":
                property_parent = parent_item
                if property_parent is None and parent_node.tag == "Item":
                    property_parent = parent_node
                normalized_property = self.normalize_item_property(
                    child, property_parent
                )
                if normalized_property is None:
                    parent_node.remove(child)
                else:
                    normalized_property.tail = child.tail
                    parent_node.replace(child, normalized_property)
            elif child.tag == "ExpressionConfig":
                parent_node.replace(child, self.normalize_expression_config(child))
            elif child.tag == "ItemLink":
                parent_node.replace(child, self.normalize_expression_item_link(child))
            elif child.tag == "ItemLinkCollection":
                for link in list(child):
                    if link.tag == "ItemLink":
                        child.replace(
                            link,
                            self.normalize_expression_item_link(
                                link, child.xpath("ItemLink")
                            ),
                        )
            elif child.tag == "Item":
                normalized_item = self.normalize_item(child)
                normalized_item.tail = child.tail
                parent_node.replace(child, normalized_item)
            elif (
                child.tag == "ItemClassAssociation"
                and "classDefinitionId" in child.attrib
            ):
                normalized_association = self.normalize_item_class_association(child)
                normalized_association.tail = child.tail
                parent_node.replace(child, normalized_association)
            elif child.tag == "HistoricalExpressionConfig":
                # Process nested HistoricalFieldExpression structure
                for expr_config in child.xpath("ExpressionConfig[@format='']"):
                    normalized_config = self.normalize_historical_field_expression(
                        expr_config
                    )
                    child.replace(expr_config, normalized_config)
                self._normalize_item_children(child, parent_item)
            else:
                self._normalize_item_children(child, parent_item)

    def add_item_attributes(self, item_node):
        if item_node.get("id"):
            item_node.set("hash", sha1(item_node.get("id")))
        else:
            hash_input = "|".join(
                [
                    item_node.get("name", ""),
                    item_node.get("type", ""),
                    item_node.get("class", ""),
                ]
            )
            item_node.set("hash", sha1(hash_input))

        if item_node.get("id"):
            full_name = self.get_item_full_name(item_node)
            item_node.set("fullName", full_name)

        if item_node.get("class") == "true":
            item_node.set("class", "true")

        self.add_translation(item_node)

    def add_property_display_order(self, item_node):
        if item_node.xpath("Property[@name='DisplayOrder']"):
            return

        default_display_order = self._get_default_display_order()
        property_node = etree.Element("Property")
        property_node.set("name", "DisplayOrder")
        property_node.text = default_display_order
        item_node.append(property_node)

    def _get_default_display_order(self):
        reference_versions = self.root.xpath(
            "Reference[@name='Citect.Ampla.StandardItems']/@version"
        )
        if not reference_versions:
            return "0"

        version_parts = reference_versions[0].split(".")
        major_version = version_parts[0] if len(version_parts) > 1 else ""
        minor_version = version_parts[1] if len(version_parts) > 2 else ""
        try:
            major = float(major_version)
            minor = float(minor_version)
        except ValueError:
            return "0"
        if major > 4 or (major == 4 and minor >= 2):
            return "50000"
        return "0"

    def exclude_runstate_property(self, property_node):
        return property_node.get("name") == "RunState"

    def exclude_display_order_index(self, property_node):
        return property_node.get("name") == "DisplayOrderIndex"

    def exclude_display_order_group(self, property_node):
        return property_node.get("name") == "DisplayOrderGroup"

    def exclude_property_mask_sets(self, property_node):
        return property_node.get("name") == "PropertyMaskSets"

    def exclude_data_source_property(self, property_node):
        return property_node.get("name") == "DataSource"

    def exclude_definition_property(self, property_node):
        exclude = [
            "RunState",
            "DisplayOrderIndex",
            "DisplayOrderGroup",
            "PropertyMaskSets",
            "DataSource",
            "Definition",
        ]
        return property_node.get("name") in exclude

    def normalize_item_class_association(self, association_node):
        class_id = association_node.get("classDefinitionId")
        prop = etree.Element("Property")
        prop.set("name", "ClassAssociation")
        prop.set("class", "true")

        item_link = etree.Element("ItemLink")
        item_link.set("targetID", class_id or "")
        item_link.set("absolutePath", self.get_class_full_name_by_id(class_id or ""))
        prop.append(item_link)
        return prop

    def normalize_equipment_template_target(self, property_node):
        normalized = copy_node(property_node)
        normalized.set("class", "true")
        normalized.text = None
        normalized[:] = []

        target_id = property_node.get("classDefinitionId", "")
        path_class_id = property_node.xpath("string(.)")
        item_link = etree.Element("ItemLink")
        item_link.set("targetID", target_id)
        item_link.set("absolutePath", self.get_class_full_name_by_id(path_class_id))
        normalized.append(item_link)
        return normalized

    def normalize_expression_config(self, expression_config):
        normalized = copy_node(expression_config)
        item_links = expression_config.xpath("ItemLinkCollection/ItemLink")
        normalized.set(
            "text",
            self.format_expression(expression_config.get("format", ""), item_links),
        )

        for child in list(normalized):
            if child.tag == "ItemLinkCollection":
                for link in list(child):
                    if link.tag == "ItemLink":
                        child.replace(
                            link, self.normalize_expression_item_link(link, item_links)
                        )
            elif child.tag == "ItemLink":
                normalized.replace(
                    child, self.normalize_expression_item_link(child, item_links)
                )
            else:
                self._normalize_item_children(child, None)
        return normalized

    def normalize_expression_item_link(self, item_link, item_links=None):
        normalized = copy_node(item_link)
        if item_links is not None:
            nested_item_links = normalized.xpath("ItemLinkCollection/ItemLink")
            normalized.set(
                "expressionFormat",
                self.format_expression(normalized.get("format", ""), nested_item_links),
            )
        return normalized

    def get_project_full_name(self, item_id):
        item = self.items_by_id.get(item_id)
        if item is None:
            return ""

        ancestors = item.xpath("ancestor-or-self::Item[@id]")
        path_parts = []
        for ancestor in ancestors:
            name = ancestor.get("name", "")
            if any(
                character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                for character in name
            ):
                name = f"[{name}]"
            path_parts.append(name)
        if not path_parts:
            return ""
        return "Project." + ".".join(path_parts)

    def get_project_full_name_by_id(self, item_id):
        return self.get_project_full_name(item_id)

    def get_item_full_name(self, item):
        source_item = self.items_by_id.get(item.get("id"), item)
        return ".".join(
            ancestor.get("name", "")
            for ancestor in source_item.xpath("ancestor-or-self::Item[@id]")
        )

    def get_class_full_name_by_id(self, class_id):
        class_nodes = self.root.xpath(f"//ClassDefinition[@id='{class_id}']")
        if not class_nodes:
            return ""
        class_node = class_nodes[0]
        ancestors = class_node.xpath("ancestor::ClassDefinition")
        path_parts = [anc.get("name") or anc.get("id") for anc in reversed(ancestors)]
        path_parts.append(class_node.get("name") or class_node.get("id"))
        return ".".join(path_parts)

    def format_expression(self, format_string, item_links):
        result = format_string
        if isinstance(item_links, dict):
            for token, replacement in item_links.items():
                result = self.find_replace(result, token, replacement)
            return result

        for index, item_link in enumerate(item_links):
            token = f"#ItemReference{index}#"
            replacement = self.get_project_full_name(item_link.get("targetID"))
            result = self.find_replace(result, token, replacement)
        return result

    def find_replace(self, text, token, replacement):
        return text.replace(token, replacement)

    def normalize_cycle_manager_cycles(self, property_node):
        """
        Convert Cycles property of a CycleManager item.
        Transforms nested Property/Item elements into ItemLink elements with absolutePath.

        XSLT template:
        match="Item[@type='Citect.Ampla.General.Server.RecordStates.CycleManager']/Property[@name='Cycles']"
        """
        normalized = copy_node(property_node)
        normalized.attrib.clear()
        if property_node.get("name") is not None:
            normalized.set("name", property_node.get("name"))
        normalized.text = None

        # Convert nested Item elements to ItemLink elements
        normalized[:] = []
        item_elements = property_node.xpath("Property/Item")
        if not item_elements:
            item_elements = property_node.xpath("Item")
        for item_elem in item_elements:
            item_link = etree.Element("ItemLink")
            # The item element's text is the absolute path.
            absolute_path = item_elem.text or ""
            item_link.set("absolutePath", absolute_path)
            normalized.append(item_link)

        return normalized

    def normalize_resolver_item(self, resolver_item):
        """
        Normalize a Resolver item (Citect.Ampla.Metrics.Server.Resolvers.Resolver).
        Injects default Action and ResolverOperation properties if missing.

        XSLT template:
        match="Item[@type='Citect.Ampla.Metrics.Server.Resolvers.Resolver']"
        """
        normalized = copy_node(resolver_item)

        # Add default Action property if missing
        if not normalized.xpath("./Property[@name='Action']"):
            action_prop = etree.Element("Property")
            action_prop.set("name", "Action")
            action_prop.text = "Module"
            self._insert_before_child_items(normalized, action_prop)

        # Add default ResolverOperation property if missing
        if not normalized.xpath("./Property[@name='ResolverOperation']"):
            resolver_op_prop = etree.Element("Property")
            resolver_op_prop.set("name", "ResolverOperation")
            resolver_op_prop.text = "Sum"
            self._insert_before_child_items(normalized, resolver_op_prop)

        return normalized

    def _insert_before_child_items(self, item, property_node):
        child_items = item.xpath("./Item")
        if child_items:
            item.insert(item.index(child_items[0]), property_node)
        else:
            item.append(property_node)

    def normalize_user_item(self, user_item):
        normalized = copy_node(user_item)
        if not normalized.xpath("./Property[@name='Authentication']"):
            auth_prop = etree.Element("Property")
            auth_prop.set("name", "Authentication")
            auth_prop.text = "WindowsIntegrated"
            self._insert_before_child_items(normalized, auth_prop)

        return normalized

    def normalize_historical_field_expression(self, expression_config):
        """
        Annotate ExpressionConfig with a warning message when required metadata is missing.
        Checks if both CaptureValueForManualRecords and RefreshOnManualEntry are True.

        XSLT template:
        match="Item[@id]/Property[@name='HistoricalFieldExpression']/HistoricalExpressionConfig/ExpressionConfig[@format='']"
        """
        normalized = copy_node(expression_config)

        # Navigate up to the Property to check sibling properties
        # The expression_config is under Property -> HistoricalExpressionConfig -> ExpressionConfig
        parent_hist_config = expression_config.getparent()  # HistoricalExpressionConfig
        if parent_hist_config is None:
            return normalized

        parent_property = parent_hist_config.getparent()  # Property
        if parent_property is None:
            return normalized

        parent_item = parent_property.getparent()  # Item
        if parent_item is None:
            return normalized

        # Check for CaptureValueForManualRecords and RefreshOnManualEntry in sibling properties
        capture_manual = parent_item.xpath(
            "Property[@name='CaptureValueForManualRecords' and text()='True']"
        )
        refresh_manual = parent_item.xpath(
            "Property[@name='RefreshOnManualEntry' and text()='True']"
        )

        # If both are True, add a warning message attribute
        if capture_manual and refresh_manual:
            normalized.set("message", "No expression specified for Manual records.")

        return normalized

    def normalize_home_property(self, property_node):
        normalized = etree.Element("Property")
        normalized.set("name", "Home")
        home_count = sum(
            len(descriptor.xpath("Property[@name='LocationType' and text()='Home']"))
            for descriptor in property_node.xpath(
                ".//*[@type=$type]", type=FAVORITE_DESCRIPTOR_TYPE
            )
        )
        text_elem = etree.SubElement(normalized, "text")
        text_elem.text = f"{{{home_count} Favourite(s)}}"
        for descriptor in property_node.xpath(
            "Property[@type=$type]", type=FAVORITE_DESCRIPTOR_TYPE
        ):
            favorite = self.normalize_favorite_descriptor(descriptor)
            if favorite is not None:
                normalized.append(favorite)

        return normalized

    def normalize_favorites_property(self, property_node):
        normalized = etree.Element("Property")
        normalized.set("name", "Favorites")
        favorite_descriptors = property_node.xpath(
            ".//*[@type=$type]", type=FAVORITE_DESCRIPTOR_TYPE
        )
        num_favorites = len(favorite_descriptors)

        if num_favorites > 0:
            text_elem = etree.Element("text")
            text_elem.text = f"{{{num_favorites} Favourite(s)}}"
            corrupt_count = sum(
                len(
                    descriptor.xpath(
                        "Property[@name='LocationType' and text() != 'Favorite']"
                    )
                )
                for descriptor in favorite_descriptors
            )
            if corrupt_count:
                text_elem.set("isCorrupt", "true")
            normalized.append(text_elem)
            for collection in property_node.xpath(
                "Property[@type=$type]", type=FAVORITE_COLLECTION_TYPE
            ):
                normalized.append(self.normalize_favorite_collection(collection))
        else:
            normalized.text = "{0 Favorite(s)}"
        return normalized

    def normalize_favorite_descriptor(self, descriptor):
        if not descriptor.xpath("Property[@name='Location']"):
            return None

        favorite = etree.Element("Favorite")
        attributes = (
            ("name", "Name", True),
            ("module", "Module", True),
            ("filter", "Filter", False),
            ("location", "Location", False),
            ("recurse", "Recurse", False),
            ("view", "ViewName", False),
        )
        for output_name, property_name, required in attributes:
            values = descriptor.xpath("Property[@name=$name]", name=property_name)
            if required or values:
                favorite.set(
                    output_name,
                    "".join(values[0].itertext()) if values else "",
                )
        return favorite

    def normalize_favorite_collection(self, collection):
        favorites = etree.Element("Favorites")
        names = collection.xpath("Property[@name='Name']")
        favorites.set("name", "".join(names[0].itertext()) if names else "")
        for nested_collection in collection.xpath(
            "Item[@type=$type]", type=FAVORITE_COLLECTION_TYPE
        ):
            favorites.append(self.normalize_favorite_collection(nested_collection))
        for descriptor in collection.xpath(
            "Item[@type=$type]", type=FAVORITE_DESCRIPTOR_TYPE
        ):
            favorite = self.normalize_favorite_descriptor(descriptor)
            if favorite is not None:
                favorites.append(favorite)
        return favorites

    def copy_node(self, node):
        return copy_node(node)

    def _remove_comments(self, node):
        for child in list(node):
            if isinstance(child, etree._Comment):
                node.remove(child)
            else:
                self._remove_comments(child)
