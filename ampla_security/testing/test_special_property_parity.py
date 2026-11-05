from pathlib import Path

from lxml import etree

from ampla_security.normalization.project_normalizer import ProjectNormalizer

SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
PROJECT_XML = f"""\
<Ampla name="SpecialPropertyParity">
  <Reference id="standard-items" name="Citect.Ampla.StandardItems" version="4.4.0"/>
  <Item id="generic" name="Generic">
    <Property name="GenericSoap" extra="dropped">
      <soap:Envelope xmlns:soap="{SOAP_NS}">
        <soap:Body><soap:Value>ignored</soap:Value></soap:Body>
      </soap:Envelope>
    </Property>
    <Property name="EquipmentTypes" source="kept">A,B,,C</Property>
    <Property name="SubscriptionsCRLF">placeholder</Property>
    <Property name="SubscriptionsCR">placeholder</Property>
    <Property name="SubscriptionsLF">placeholder</Property>
    <Property name="SubscriptionsMalformed">placeholder</Property>
  </Item>
  <Item id="adapter" name="Adapter"
        type="Citect.Ampla.Connectors.OleDbConnector.OleDbAdapter">
    <Property name="Query" extra="dropped">
      <soap:Envelope xmlns:soap="{SOAP_NS}">
        <soap:Body>
          <Response xmlns=""><Record><Value>42</Value><Empty/></Record></Response>
        </soap:Body>
      </soap:Envelope>
    </Property>
    <Property name="EmptyQuery">
      <soap:Envelope xmlns:soap="{SOAP_NS}">
        <soap:Body><soap:Value>ignored</soap:Value></soap:Body>
      </soap:Envelope>
    </Property>
  </Item>
</Ampla>
"""

STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Project.Normalize.xslt"
)


def _source_tree() -> etree._ElementTree:
    tree = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    properties = {
        "SubscriptionsCRLF": (
            "Subscription|Area.One|OnChange|Handler.One|Value=1\r\n"
            "AutoSubscription|Area.Two|OnStart|Handler.Two"
        ),
        "SubscriptionsCR": (
            "Subscription|Area.One|OnChange|Handler.One\r"
            "AutoSubscription|Area.Two|OnStart|Handler.Two"
        ),
        "SubscriptionsLF": (
            "Subscription|Area.One|OnChange|Handler.One\n"
            "AutoSubscription|Area.Two|OnStart|Handler.Two"
        ),
        "SubscriptionsMalformed": (
            "InvalidLine\rSubscription|OnlyPath\r"
            "Subscription|Area|Event|Handler|Expression|Extra"
        ),
    }
    for name, value in properties.items():
        prop = tree.xpath(".//Property[@name=$name]", name=name)[0]
        prop.text = value
    return tree


def _canonical_xml(node: etree._Element) -> bytes:
    for element in node.iter():
        element.attrib.pop("hash", None)
        if element.text is not None and not element.text.strip():
            element.text = None
        if element.tail is not None and not element.tail.strip():
            element.tail = None
    return etree.tostring(node, method="c14n", with_comments=True)


def _xslt_output(source: etree._ElementTree) -> etree._ElementTree:
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    output = transform(source)
    return etree.ElementTree(etree.fromstring(etree.tostring(output)))


def test_soap_equipment_and_subscription_properties_match_xslt():
    source = _source_tree()
    python_output = ProjectNormalizer(source).normalize()
    xslt_output = _xslt_output(_source_tree())

    for item_id, property_names in (
        (
            "generic",
            (
                "GenericSoap",
                "EquipmentTypes",
                "SubscriptionsCRLF",
                "SubscriptionsCR",
                "SubscriptionsLF",
                "SubscriptionsMalformed",
            ),
        ),
        ("adapter", ("Query", "EmptyQuery")),
    ):
        for name in property_names:
            python_prop = python_output.xpath(
                ".//Item[@id=$item_id]/Property[@name=$name]",
                item_id=item_id,
                name=name,
            )[0]
            xslt_prop = xslt_output.xpath(
                ".//Item[@id=$item_id]/Property[@name=$name]",
                item_id=item_id,
                name=name,
            )[0]
            assert _canonical_xml(python_prop) == _canonical_xml(xslt_prop)


def test_generic_soap_and_oledb_flattening():
    output = ProjectNormalizer(_source_tree()).normalize()

    generic_soap = output.xpath(".//Item[@id='generic']/Property[@name='GenericSoap']")[
        0
    ]
    assert generic_soap.attrib == {"name": "GenericSoap", "isSoap": "true"}
    assert generic_soap.text == "{SOAP}"

    adapter_query = output.xpath(".//Item[@id='adapter']/Property[@name='Query']")[0]
    assert adapter_query.attrib == {"name": "Query", "isSoap": "true"}
    assert [
        (node.get("name"), node.text) for node in adapter_query.findall("soap-property")
    ] == [("Response", "42"), ("Record", "42"), ("Value", "42")]

    empty_query = output.xpath(".//Item[@id='adapter']/Property[@name='EmptyQuery']")[0]
    assert empty_query.text == "{SOAP}"


def test_equipment_types_csv_preserves_order_empty_entries_and_attributes():
    output = ProjectNormalizer(_source_tree()).normalize()
    equipment_types = output.xpath(
        ".//Item[@id='generic']/Property[@name='EquipmentTypes']"
    )[0]

    assert equipment_types.attrib == {"name": "EquipmentTypes", "source": "kept"}
    assert equipment_types.xpath("./ItemLink/@absolutePath") == ["A", "B", "", "C"]


def test_subscription_separator_rules_attributes_and_malformed_omissions():
    output = ProjectNormalizer(_source_tree()).normalize()
    item = output.xpath(".//Item[@id='generic']")[0]

    crlf_links = item.xpath("./Property[@name='SubscriptionsCRLF']/ItemLink")
    assert [link.get("type") for link in crlf_links] == [
        "Subscription",
        "AutoSubscription",
    ]
    assert crlf_links[0].attrib == {
        "type": "Subscription",
        "absolutePath": "Area.One",
        "event": "OnChange",
        "handler": "Handler.One",
        "expressionMatch": "Value=1",
    }
    assert crlf_links[1].attrib == {
        "type": "AutoSubscription",
        "absolutePath": "Area.Two",
        "event": "OnStart",
        "handler": "Handler.Two",
    }

    cr_links = item.xpath("./Property[@name='SubscriptionsCR']/ItemLink")
    assert len(cr_links) == 2
    assert cr_links[1].get("type") == "AutoSubscription"

    lf_links = item.xpath("./Property[@name='SubscriptionsLF']/ItemLink")
    assert len(lf_links) == 1
    assert lf_links[0].get("handler") == ("Handler.One\nAutoSubscription")
    assert lf_links[0].get("expressionMatch") is None
    assert any(
        "Unexpected Subscription [4]: Area.Two|OnStart|Handler.Two"
        in (comment.text or "")
        for comment in lf_links[0].iter(etree.Comment)
    )

    malformed = item.xpath("./Property[@name='SubscriptionsMalformed']")[0]
    comments = [child.text or "" for child in malformed.iter(etree.Comment)]
    assert any("Unexpected Subscription [0]: InvalidLine" in text for text in comments)
    assert any("Unexpected Subscription [1]: OnlyPath" in text for text in comments)
    assert any(
        "Unexpected Subscription [4]: Expression|Extra" in text for text in comments
    )
