from pathlib import Path

from lxml import etree

from ampla_security.normalization.project_normalizer import ProjectNormalizer

PROJECT_XML = """\
<Ampla name="PathExpressionParity">
  <Reference id="standard-items" name="Citect.Ampla.StandardItems" version="4.4.0"/>
  <Item id="root" name="Root">
    <Item id="area" name="Area 1">
      <Item id="pump" name="Pump/A"/>
      <Item id="unnamed"/>
      <Property name="Expression">
        <ExpressionConfig format="#ItemReference0# + #ItemReference0# + #ItemReference1# + #ItemReference2#">
          <ItemLinkCollection>
            <ItemLink targetID="pump"/>
            <ItemLink targetID="unnamed"/>
            <ItemLink targetID="missing-id"/>
            <ItemLink targetID="pump" format="Use #ItemReference0#">
              <ItemLinkCollection>
                <ItemLink targetID="unnamed"/>
              </ItemLinkCollection>
            </ItemLink>
          </ItemLinkCollection>
        </ExpressionConfig>
      </Property>
      <Item id="matrix" name="Matrix"
            type="Citect.Ampla.General.Server.DecisionMatrix">
        <Item id="input" name="Input A"
              type="Citect.Ampla.StandardItems.CalculatedVariable"/>
      </Item>
    </Item>
  </Item>
</Ampla>
"""

STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Project.Normalize.xslt"
)


def _xslt_output(source: etree._ElementTree) -> etree._ElementTree:
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    output = transform(source)
    return etree.ElementTree(etree.fromstring(etree.tostring(output)))


def _canonical_xml(node: etree._Element) -> bytes:
    for element in node.iter():
        element.attrib.pop("hash", None)
        if element.text is not None and not element.text.strip():
            element.text = None
        if element.tail is not None and not element.tail.strip():
            element.tail = None
    return etree.tostring(node, method="c14n")


def test_project_full_names_and_expression_links_match_xslt():
    source = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    python_output = ProjectNormalizer(source).normalize()
    xslt_output = _xslt_output(
        etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    )

    for item_id in ("root", "area", "pump", "unnamed", "matrix", "input"):
        python_item = python_output.xpath(".//Item[@id=$id]", id=item_id)[0]
        xslt_item = xslt_output.xpath(".//Item[@id=$id]", id=item_id)[0]
        assert python_item.get("fullName") == xslt_item.get("fullName")
        assert python_item.get("name") == xslt_item.get("name")

    assert python_output.xpath(".//Item[@id='root']/@fullName") == ["Root"]
    assert python_output.xpath(".//Item[@id='area']/@fullName") == ["Root.Area 1"]
    assert python_output.xpath(".//Item[@id='pump']/@fullName") == [
        "Root.Area 1.Pump/A"
    ]
    assert python_output.xpath(".//Item[@id='unnamed']/@fullName") == ["Root.Area 1."]
    assert python_output.xpath(".//Item[@id='unnamed']/@name") == []

    python_expression = python_output.xpath(".//ExpressionConfig")[0]
    xslt_expression = xslt_output.xpath(".//ExpressionConfig")[0]
    assert _canonical_xml(python_expression) == _canonical_xml(xslt_expression)
    assert python_expression.get("text") == (
        "Project.Root.[Area 1].[Pump/A] + "
        "Project.Root.[Area 1].[Pump/A] + "
        "Project.Root.[Area 1]. + "
    )
    assert python_expression.xpath(
        "./ItemLinkCollection/ItemLink[@format]/@expressionFormat"
    ) == ["Use Project.Root.[Area 1]."]
    assert python_expression.xpath("./ItemLinkCollection/ItemLink/@absolutePath") == []

    matrix_input_link = python_output.xpath(".//Item[@id='matrix']/Input/ItemLink")[0]
    xslt_matrix_input_link = xslt_output.xpath(".//Item[@id='matrix']/Input/ItemLink")[
        0
    ]
    assert matrix_input_link.get("absolutePath") == xslt_matrix_input_link.get(
        "absolutePath"
    )
    assert matrix_input_link.get("absolutePath") == "Root.Area 1.Matrix.Input A"


def test_project_full_name_for_unknown_id_is_empty_like_xslt():
    source = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    normalizer = ProjectNormalizer(source)

    assert normalizer.get_project_full_name("missing-id") == ""
    assert (
        normalizer.format_expression(
            "Before #ItemReference0# after",
            [etree.Element("ItemLink", targetID="missing-id")],
        )
        == "Before  after"
    )
