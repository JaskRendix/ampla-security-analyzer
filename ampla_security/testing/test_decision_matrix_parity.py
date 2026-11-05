from pathlib import Path

from lxml import etree

from ampla_security.normalization.project_normalizer import ProjectNormalizer

PROJECT_XML = """\
<Ampla name="DecisionMatrixParity">
  <Reference id="standard-items" name="Citect.Ampla.StandardItems" version="4.4"/>
  <Item id="matrix" name="Matrix"
        type="Citect.Ampla.General.Server.DecisionMatrix">
    <Item id="rule-1" name="Rule1"
          type="Citect.Ampla.General.Server.DecisionMatrixRule">
      <Property name="InputA">True</Property>
      <Property name="DisplayOrder">300</Property>
      <Property name="DisplayOrderGroup">6</Property>
      <Item id="output" name="Output"
            type="Citect.Ampla.StandardItems.CalculatedVariable"/>
    </Item>
    <Item id="input-a" name="InputA"
          type="Citect.Ampla.StandardItems.CalculatedVariable">
      <Property name="DisplayOrder">20</Property>
    </Item>
    <Item id="input-b" name="InputB"
          type="Citect.Ampla.StandardItems.CalculatedVariable"/>
    <Property name="Description">Matrix description</Property>
    <Metadata>Ignored by the XSLT template</Metadata>
  </Item>
</Ampla>
"""

STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Project.Normalize.xslt"
)


def _canonical_xml(node: etree._Element) -> bytes:
    for element in node.iter():
        element.attrib.pop("hash", None)
        if element.tag == "Item":
            element.attrib.pop("fullName", None)
        if element.text is not None and not element.text.strip():
            element.text = None
        if element.tail is not None and not element.tail.strip():
            element.tail = None
    return etree.tostring(node, method="c14n")


def _xslt_output() -> etree._ElementTree:
    source = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    output = transform(source)
    return etree.ElementTree(etree.fromstring(etree.tostring(output)))


def test_decision_matrix_and_rule_match_xslt():
    source = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    python_output = ProjectNormalizer(source).normalize()
    xslt_output = _xslt_output()

    python_matrix = python_output.xpath(".//Item[@id='matrix']")[0]
    xslt_matrix = xslt_output.xpath(".//Item[@id='matrix']")[0]

    assert _canonical_xml(python_matrix) == _canonical_xml(xslt_matrix)
    assert python_matrix.xpath("./Input/@id") == ["input-a", "input-b"]
    assert python_matrix.xpath("./Input/@displayOrder") == ["20", "0"]
    assert python_matrix.xpath("./Input/ItemLink/@targetID") == [
        "input-a",
        "input-b",
    ]
    assert python_matrix.xpath("./Input/ItemLink/@absolutePath") == [
        "Matrix.InputA",
        "Matrix.InputB",
    ]
    assert python_matrix.find("Metadata") is None
    assert [child.tag for child in python_matrix] == [
        "Input",
        "Input",
        "Property",
        "Property",
        "Item",
        "Item",
        "Item",
    ]

    python_rule = python_matrix.xpath("./Item[@id='rule-1']")[0]
    assert python_rule.xpath("./InputRule/@name") == ["InputA", "InputB"]
    assert python_rule.xpath("./InputRule/@displayOrder") == ["20", "0"]
    assert python_rule.xpath("./InputRule/@value") == ["True", "Ignore"]
    assert python_rule.xpath("./InputRule/ItemLink/@targetID") == [
        "input-a",
        "input-b",
    ]
    assert python_rule.xpath("./Property[@name='DisplayOrderGroup']") == []
    assert [child.tag for child in python_rule] == [
        "InputRule",
        "InputRule",
        "Property",
        "Property",
        "Item",
    ]


def test_decision_matrix_adds_default_display_order_in_xslt_position():
    xml = """\
    <Ampla>
      <Reference name="Citect.Ampla.StandardItems" version="4.4"/>
      <Item id="matrix" name="Matrix"
            type="Citect.Ampla.General.Server.DecisionMatrix">
        <Item id="input" name="Input"
              type="Citect.Ampla.StandardItems.CalculatedVariable"/>
        <Item id="rule" name="Rule"
              type="Citect.Ampla.General.Server.DecisionMatrixRule"/>
      </Item>
    </Ampla>
    """
    source = etree.ElementTree(etree.fromstring(xml.encode()))
    output = ProjectNormalizer(source).normalize()
    matrix = output.xpath(".//Item[@id='matrix']")[0]

    assert matrix.xpath("./Property[@name='DisplayOrder']/text()") == ["0"]
    assert [child.tag for child in matrix] == [
        "Input",
        "Property",
        "Item",
        "Item",
    ]
    assert matrix.xpath("./Item[@id='rule']/InputRule/@value") == ["Ignore"]
