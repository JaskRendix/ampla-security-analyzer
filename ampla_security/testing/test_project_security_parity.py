from pathlib import Path

from lxml import etree

from ampla_security.normalization.project_security_extractor import (
    ProjectSecurityExtractor,
)

PROJECT_XML = """\
<Project>
  <Item id="zulu" name="Zulu" fullName="Zulu">
    <Item id="user-z-no-order" name="NoOrder" custom="preserved"
          type="Citect.Ampla.StandardItems.User">
      <Property name="DisplayOrder">not-a-number</Property>
      <Property name="Identity" marker="kept">Standalone</Property>
    </Item>
    <Item id="user-z-order" name="ZuluUser" type="Citect.Ampla.StandardItems.User">
      <Property name="DisplayOrder">10</Property>
      <Property name="Identity">  DOMAIN\\zulu  |  S-1-5-21-9  |&lt;NULL&gt;  </Property>
      <Property name="Authentication">WindowsIntegrated</Property>
      <Property name="SecurityID">S-1-5-21-9</Property>
    </Item>
  </Item>
  <Item id="alpha" name="Alpha" fullName="Alpha">
    <Item id="user-alpha-z" name="ZuluUser" type="Citect.Ampla.StandardItems.User">
      <Property name="DisplayOrder">2</Property>
    </Item>
    <Item id="user-alpha-b" name="Bravo" type="Citect.Ampla.StandardItems.User">
      <Property name="DisplayOrder">2</Property>
      <Property name="Identity"/>
    </Item>
    <Item id="user-alpha-a" name="AlphaUser" type="Citect.Ampla.StandardItems.User">
      <Property name="DisplayOrder">1</Property>
    </Item>
    <Item id="scope-z" name="ZuluScope" fullName="Alpha.Zulu"
          extra="scope-attribute">
      <Property name="DisplayOrder">10</Property>
      <Property name="InheritPermissions">False</Property>
    </Item>
    <Item id="scope-b" name="BravoScope" fullName="Alpha.Bravo">
      <Property name="DisplayOrder">2</Property>
      <Property name="InheritPermissions">False</Property>
    </Item>
    <Item id="scope-a" name="AlphaScope" fullName="Alpha.Alpha">
      <Property name="DisplayOrder">2</Property>
      <Property name="InheritPermissions">False</Property>
    </Item>
  </Item>
  <Item id="scope-zulu-parent" name="ZuluParent" fullName="ZuluParent">
    <Item id="scope-zulu" name="ZuluScope" fullName="ZuluParent.ZuluScope">
      <Property name="DisplayOrder">1</Property>
      <Property name="InheritPermissions">False</Property>
    </Item>
  </Item>
</Project>
"""

STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Project.Security.xslt"
)


def _canonical_xml(root: etree._Element) -> bytes:
    for element in root.iter():
        if element.text is not None and not element.text.strip():
            element.text = None
        if element.tail is not None and not element.tail.strip():
            element.tail = None
    return etree.tostring(root, method="c14n")


def _xslt_output(source: etree._ElementTree) -> etree._Element:
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    output = transform(source)
    return etree.fromstring(etree.tostring(output))


def test_project_security_extraction_matches_xslt():
    source = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    python_output = ProjectSecurityExtractor(source).extract().getroot()
    xslt_output = _xslt_output(source)

    assert _canonical_xml(python_output) == _canonical_xml(xslt_output)


def test_extraction_preserves_attributes_identity_whitespace_and_empty_identity():
    source = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    output = ProjectSecurityExtractor(source).extract().getroot()

    user = output.xpath("./Users/User[@id='user-z-no-order']")[0]
    assert user.attrib == {
        "id": "user-z-no-order",
        "name": "NoOrder",
        "custom": "preserved",
        "type": "Citect.Ampla.StandardItems.User",
    }
    empty_identity = user.find("Property[@name='Identity']")
    assert empty_identity is not None
    assert empty_identity.get("marker") == "kept"
    assert empty_identity.find("Identity") is not None
    assert empty_identity.find("Identity").attrib == {}
    assert empty_identity.find("Identity").text == "Standalone"

    identity = output.xpath(
        "./Users/User[@id='user-z-order']/Property[@name='Identity']/Identity"
    )[0]
    assert identity.get("name") == "  DOMAIN\\zulu  "
    assert identity.get("sid") == "  S-1-5-21-9  "
    assert identity.text == "  DOMAIN\\zulu  |  S-1-5-21-9  |<NULL>  "

    empty_value = output.xpath(
        "./Users/User[@id='user-alpha-b']/Property[@name='Identity']/Identity"
    )[0]
    assert empty_value.attrib == {}
    assert empty_value.text is None


def test_users_and_scopes_follow_xslt_sort_order_and_copy_scope_attributes():
    source = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    output = ProjectSecurityExtractor(source).extract().getroot()

    assert output.xpath("./Users/User/@id") == [
        "user-alpha-a",
        "user-alpha-b",
        "user-alpha-z",
        "user-z-no-order",
        "user-z-order",
    ]
    assert output.xpath("./Scopes/Scope/@scopeId") == [
        "00000000-0000-0000-0000-000000000000",
        "scope-a",
        "scope-b",
        "scope-z",
        "scope-zulu",
    ]
    scope = output.xpath("./Scopes/Scope[@scopeId='scope-z']")[0]
    assert scope.get("extra") == "scope-attribute"
    assert scope.get("id") == "scope-z"
