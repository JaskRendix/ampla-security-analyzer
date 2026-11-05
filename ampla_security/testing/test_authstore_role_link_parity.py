from pathlib import Path

from lxml import etree

from ampla_security.normalization.authstore_normalizer import AuthstoreNormalizer

STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Authstore.Normalize.xslt"
)


ROLE_GRAPH_XML = """\
<AzAdminManager>
  <AzApplication Name="RoleGraph">
    <AzOperation Guid="op-read" Name="Read">
      <OperationID>10</OperationID>
    </AzOperation>
    <AzOperation Guid="op-write" Name="Write">
      <OperationID>2</OperationID>
    </AzOperation>
    <AzTask Guid="base" Name="Base" Description="Base permissions"
            RoleDefinition="True">
      <OperationLink>op-read</OperationLink>
      <OperationLink>op-write</OperationLink>
    </AzTask>
    <AzTask Guid="middle" Name="Middle" Description="Middle permissions"
            RoleDefinition="True">
      <TaskLink>base</TaskLink>
      <OperationLink>op-read</OperationLink>
    </AzTask>
    <AzTask Guid="top" Name="Top" Description="Top permissions"
            RoleDefinition="True">
      <TaskLink>middle</TaskLink>
      <OperationLink>op-write</OperationLink>
    </AzTask>
    <AzRole Description="Assigned role">
      <TaskLink>top</TaskLink>
      <Member>S-1-5-21-1-2-3-1002</Member>
      <Member>S-1-5-21-1-2-3-1001</Member>
    </AzRole>
    <AzScope Name="scope-1" Description="Security scope for Area One">
      <AzRole Description="Scoped role">
        <TaskLink>middle</TaskLink>
        <Member>S-1-5-21-1-2-3-1001</Member>
      </AzRole>
    </AzScope>
  </AzApplication>
</AzAdminManager>
"""

UNRESOLVED_LINKS_XML = """\
<AzAdminManager>
  <AzApplication Name="UnresolvedLinks">
    <AzOperation Guid="op" Name="Known"/>
    <AzTask Guid="role" Name="Role" RoleDefinition="True">
      <TaskLink>missing-role</TaskLink>
      <OperationLink>missing-operation</OperationLink>
    </AzTask>
    <AzRole Description="Unresolved assignment">
      <TaskLink>missing-role</TaskLink>
    </AzRole>
  </AzApplication>
</AzAdminManager>
"""

CYCLIC_ROLE_GRAPH_XML = """\
<AzAdminManager>
  <AzApplication Name="CyclicRoles">
    <AzOperation Guid="op" Name="Read"/>
    <AzTask Guid="role-a" Name="Role A" RoleDefinition="True">
      <TaskLink>role-b</TaskLink>
      <OperationLink>op</OperationLink>
    </AzTask>
    <AzTask Guid="role-b" Name="Role B" RoleDefinition="True">
      <TaskLink>role-a</TaskLink>
      <OperationLink>op</OperationLink>
    </AzTask>
  </AzApplication>
</AzAdminManager>
"""


def _normalize_with_xslt(xml: str) -> etree._ElementTree:
    source = etree.ElementTree(etree.fromstring(xml.encode()))
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    output = transform(source)
    return etree.ElementTree(etree.fromstring(etree.tostring(output)))


def _normalize_with_python(xml: str) -> etree._ElementTree:
    source = etree.ElementTree(etree.fromstring(xml.encode()))
    return AuthstoreNormalizer(source).normalize()


def _canonical_xml(node: etree._Element) -> bytes:
    for element in node.iter():
        if element.text is not None and not element.text.strip():
            element.text = None
        if element.tail is not None and not element.tail.strip():
            element.tail = None
    return etree.tostring(node, method="c14n")


def _assigned_role_values(
    tree: etree._ElementTree,
) -> list[tuple[str, str, str, list[tuple[str, str]]]]:
    roles = []
    for role in tree.xpath("./Scopes/Scope/Role"):
        members = [
            (member.get("sid", ""), member.get("type", ""))
            for member in role.xpath("Member")
        ]
        roles.append(
            (
                role.get("roleId", ""),
                role.get("name", ""),
                role.get("description", ""),
                members,
            )
        )
    return roles


def test_role_and_operation_links_match_xslt():
    python_output = _normalize_with_python(ROLE_GRAPH_XML)
    xslt_output = _normalize_with_xslt(ROLE_GRAPH_XML)

    for section in ("Operations", "RoleDefinitions"):
        python_section = python_output.find(section)
        xslt_section = xslt_output.find(section)
        assert python_section is not None
        assert xslt_section is not None
        assert _canonical_xml(python_section) == _canonical_xml(xslt_section)
    assert python_output.xpath(
        "./RoleDefinitions/RoleDefinition[@roleId='top']/RoleLink/Operation/@name"
    ) == ["Read"]
    assert python_output.xpath(
        "./Operations/Operation[@name='Read']/Links//RoleLink/@roleId"
    ) == ["base", "middle", "top", "middle", "top"]
    assert python_output.xpath(
        "./Operations/Operation[@name='Read']/Links/RoleLink[1]/RoleLink/@roleId"
    ) == ["middle"]
    assert _assigned_role_values(python_output) == _assigned_role_values(xslt_output)
    assert _assigned_role_values(python_output) == [
        (
            "top",
            "Top",
            "Assigned role",
            [
                ("S-1-5-21-1-2-3-1001", "windows"),
                ("S-1-5-21-1-2-3-1002", "windows"),
            ],
        ),
        (
            "middle",
            "Middle",
            "Scoped role",
            [("S-1-5-21-1-2-3-1001", "windows")],
        ),
    ]


def test_dangling_role_and_operation_links_match_xslt():
    python_output = _normalize_with_python(UNRESOLVED_LINKS_XML)
    xslt_output = _normalize_with_xslt(UNRESOLVED_LINKS_XML)

    python_role_definitions = python_output.find("RoleDefinitions")
    xslt_role_definitions = xslt_output.find("RoleDefinitions")
    assert python_role_definitions is not None
    assert xslt_role_definitions is not None
    assert _canonical_xml(python_role_definitions) == _canonical_xml(
        xslt_role_definitions
    )
    dangling_role_link = python_output.xpath(
        "./RoleDefinitions/RoleDefinition/RoleLink"
    )[0]
    assert dangling_role_link.attrib == {"name": "", "roleId": ""}
    dangling_operation = python_output.xpath(
        "./RoleDefinitions/RoleDefinition/Operation"
    )[0]
    assert dangling_operation.attrib == {"name": ""}


def test_cyclic_role_inheritance_terminates_without_repeating_a_role():
    output = _normalize_with_python(CYCLIC_ROLE_GRAPH_XML)
    role_links = output.xpath("./Operations/Operation/Links/RoleLink")

    assert len(role_links) == 2
    for role_link in role_links:
        nested_ids = [role_link.get("roleId")]
        nested_ids.extend(role_link.xpath(".//RoleLink/@roleId"))
        assert len(nested_ids) == len(set(nested_ids))
        assert len(nested_ids) == 2
