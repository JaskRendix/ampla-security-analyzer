from pathlib import Path

from lxml import etree

from ampla_security.normalization.authstore_normalizer import AuthstoreNormalizer

AUTHSTORE_XML = """\
<AzAdminManager>
  <AzApplication Name="ParityApp">
    <AzOperation Guid="operation-2" Name="Second" Description="Second operation">
      <OperationID>20</OperationID>
    </AzOperation>
    <AzOperation Guid="operation-1" Name="First" Description="First operation">
      <OperationID>1</OperationID>
    </AzOperation>
    <AzTask Guid="role-1" Name="Operator" Description="Runs operations"
            RoleDefinition="True"/>
    <AzScope Name="scope-1" Description="Security scope for Area One"/>
  </AzApplication>
</AzAdminManager>
"""

PROJECT_SECURITY_XML = """\
<Security>
  <Users>
    <User id="user-2" name="Bob" hash="hash-2" fullName="Project.Bob">
      <Property name="Authentication">WindowsIntegrated</Property>
    </User>
    <User id="user-1" name="Alice" hash="hash-1" fullName="Project.Alice">
      <Property name="DisplayOrder">2</Property>
      <Property name="Authentication">WindowsIntegrated</Property>
      <Property name="Identity">
        <Identity name="DOMAIN\\\\alice" sid="S-1-5-21-1-2-3-1001">
          DOMAIN\\\\alice|S-1-5-21-1-2-3-1001|&lt;NULL&gt;
        </Identity>
      </Property>
      <Property name="SecurityID">S-1-5-21-1-2-3-1001</Property>
    </User>
  </Users>
  <Scopes>
    <Scope name="{Global}" scopeId="00000000-0000-0000-0000-000000000000"/>
    <Scope name="Area One" scopeId="scope-1"/>
  </Scopes>
</Security>
"""

STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Authstore.Normalize.xslt"
)


def _canonical_xml(tree: etree._ElementTree) -> bytes:
    root = tree.getroot()
    for node in root.iter():
        if node.text is not None and not node.text.strip():
            node.text = None
        if node.tail is not None and not node.tail.strip():
            node.tail = None
    return etree.tostring(root, method="c14n")


def test_authstore_normalization_matches_xslt_security_schema(tmp_path):
    authstore_tree = etree.ElementTree(etree.fromstring(AUTHSTORE_XML.encode()))
    project_security_tree = etree.ElementTree(
        etree.fromstring(PROJECT_SECURITY_XML.encode())
    )
    normalizer = AuthstoreNormalizer(authstore_tree)
    normalizer.set_project_security(project_security_tree)
    python_output = normalizer.normalize()

    project_security_path = tmp_path / "project_security.xml"
    project_security_tree.write(str(project_security_path), encoding="utf-8")
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    xslt_output = transform(
        authstore_tree,
        projectSecurity=etree.XSLT.strparam(str(project_security_path)),
    )
    xslt_tree = etree.ElementTree(etree.fromstring(etree.tostring(xslt_output)))

    assert python_output.getroot().tag == "Security"
    assert [child.tag for child in python_output.getroot()] == [
        "Operations",
        "RoleDefinitions",
        "Scopes",
        "Users",
    ]
    assert python_output.xpath("./Users/User/@name") == ["Bob", "Alice"]
    assert _canonical_xml(python_output) == _canonical_xml(xslt_tree)


def test_authstore_security_sections_exist_without_project_security():
    authstore_tree = etree.ElementTree(etree.fromstring(AUTHSTORE_XML.encode()))
    output = AuthstoreNormalizer(authstore_tree).normalize().getroot()

    assert output.tag == "Security"
    assert output.get("name") == "ParityApp"
    assert output.xpath("./Operations/Operation/@name") == ["First", "Second"]
    assert output.xpath("./RoleDefinitions/RoleDefinition/@name") == ["Operator"]
    assert output.xpath("./Scopes/Scope/@name") == ["{Global}", "Area One"]
    assert output.xpath("./Users") == [output.find("Users")]
