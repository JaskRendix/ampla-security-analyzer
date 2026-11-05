# **Normalization Mapping**

This document maps all transforming templates in:

- `Project.Normalize.xslt`
- `Authstore.Normalize.xslt`

to their Python function equivalents.

---

## **Project.Normalize.xslt — Template → Function Mapping**

| XSLT Template | Python Function |
|---|---|
| `match="/"` | **normalize_document** |
| `match="/CitectIIM"` | **normalize_project_citect_iim** |
| `match="/Ampla"` | **normalize_project_ampla** |
| `match="CitectIIM/@*"` | **normalize_project_attribute** |
| `match="Ampla/@*"` | **normalize_project_attribute** |
| `match="Reference"` | **normalize_reference** |
| `match="Type"` | **normalize_type** |
| `match="ClassDefinition[@id]"` | **normalize_class_definition** |
| `match="Item[@id]/Property"` | **normalize_item_property** |
| `match="Item[@id]/Property[@name='RunState']"` | **exclude_runstate_property** |
| `match="Item[@id]/Property[@name='DisplayOrderIndex']"` | **exclude_display_order_index** |
| `match="Item[@id]/Property[@name='DisplayOrderGroup']"` | **exclude_display_order_group** |
| `match="Item[@id]/Property[@name='PropertyMaskSets']"` | **exclude_property_mask_sets** |
| `match="Item[@id]/Property[@name='DataSource']"` | **exclude_data_source_property** |
| `match="Item[@id]/Property[@name='Definition']"` | **exclude_definition_property** |
| `match="Item[@id]"` | **normalize_item** |
| `name="addItemAttributes"` | **add_item_attributes** |
| `name="addTranslation"` / `name="getTranslation"` | **add_translation** |
| `name="addDefaultProperty"` | **add_default_property** |
| `name="addPropertyDisplayOrder"` | **add_property_display_order** |
| `match="node()"` | **copy_node** |
| `match="ItemClassAssociation[@classDefinitionId]"` | **normalize_item_class_association** |
| `match="Item[@type='Citect.Ampla.General.Server.Templating.EquipmentTemplate']/Property[@name='TargetEquipmentClass']"` | **normalize_equipment_template_target** |
| `match="ExpressionConfig"` | **normalize_expression_config** |
| `match="ExpressionConfig/ItemLinkCollection/ItemLink"` | **normalize_expression_item_link** |
| `name="getProjectFullName"` | **get_project_full_name** |
| `name="formatExpression"` | **format_expression** |
| `name="findReplace"` | **find_replace** |
| `match="Item[@type='Citect.Ampla.General.Server.RecordStates.CycleManager']/Property[@name='Cycles']"` | **normalize_cycle_manager_cycles** |
| `match="Item[@type='Citect.Ampla.Metrics.Server.Resolvers.Resolver']"` | **normalize_resolver_item** |
| `match="Item[@type='Citect.Ampla.StandardItems.User']"` | **normalize_user_item** |
| `match="Item[@id]/Property[@name='HistoricalFieldExpression']/HistoricalExpressionConfig/ExpressionConfig[@format='']"` | **normalize_historical_field_expression** |
| `match="Property[@name='Home']"` | **normalize_home_property** |
| `match="Property[@name='Favorites']"` | **normalize_favorites_property** |
| `match="Property[SOAP-ENV:Envelope]"` | **normalize_soap_property** |
| `match="Property[@name='EquipmentTypes']"` | **normalize_equipment_types_property** |
| `match="Property[contains(@name, 'Subscription')]"` | **normalize_subscriptions_property** |
| `match="Property[SOAP-ENV:Envelope]` on OleDbAdapter items | **normalize_oledb_soap_property** |
| `csvToItemLink` / subscription parsing templates | **normalize_equipment_types_property**, **normalize_subscriptions_property** |

---

## **Authstore.Normalize.xslt — Template → Function Mapping**

| XSLT Template | Python Function |
|---|---|
| `match="/"` | **normalize_authstore_root** |
| `match="/AzAdminManager/AzApplication"` | **normalize_authorization_application** |
| `match="AzOperation"` | **normalize_operation** |
| `name="add-role-link"` | **add_role_link** |
| `match="AzRole"` | **normalize_role** |
| `match="Member"` | **normalize_member** |
| `match="AzScope"` | **normalize_scope** |
| `name="checkScopeInProject"` | **check_scope_in_project** |
| `name="addProjectScopes"` | **add_project_scopes** |
| `match="AzTask[@RoleDefinition='True']"` | **normalize_role_definition** |
| `match="TaskLink"` | **normalize_task_link** |
| `match="OperationLink"` | **normalize_operation_link** |
| `name="addUser"` | **resolve_user** |
| `name="lookupWellKnownSid"` | **lookup_well_known_sid** |
| `match="User"` | **normalize_user** |
| `match="User" mode="by-identity"` | **normalize_user_by_identity** |
| `match="User" mode="by-security-id"` | **normalize_user_by_security_id** |
| `match="Identity"` | **normalize_identity** |
| `match="Property[@name]"` | **normalize_named_property** |
| `match="@*"` | **copy_attribute** |

---

## **Notes**
- Only templates that transform, filter, or extract data are included.
- Named templates map to standalone helpers.
- Exclusion templates map to explicit Python exclusion logic.
- Translation loading is performed by `ProjectNormalizer._load_translations`;
  translation lookup is applied while normalizing items and class definitions.
- Special-property mapping also covers SOAP flattening, EquipmentTypes, and
  subscription conversion.
- This table records the implemented mappings; it does not imply byte-for-byte
  identity where the parity strategy documents a justified difference.
