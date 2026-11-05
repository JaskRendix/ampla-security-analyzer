from pathlib import Path

from lxml import etree

from ampla_security.normalization.project_normalizer import ProjectNormalizer

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "excluded_properties"
STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Project.Normalize.xslt"
)

EXCLUDED_NAMES = (
    "RunState",
    "DisplayOrderIndex",
    "DisplayOrderGroup",
    "PropertyMaskSets",
    "DataSource",
    "Definition",
)
RETAINED_PROPERTIES = {
    "parent": (
        "RunStateValue",
        "DisplayOrderIndexes",
        "DisplayOrderGroupName",
        "PropertyMaskSetsExtra",
        "DataSources",
        "Definitions",
    ),
    "nested": ("DefinitionExtra",),
}


def _xslt_output() -> etree._ElementTree:
    source = etree.parse(str(FIXTURE_DIR / "project.xml"))
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    result = transform(source)
    return etree.ElementTree(etree.fromstring(etree.tostring(result)))


def _canonical_xml(node: etree._Element) -> bytes:
    return etree.tostring(node, method="c14n")


def test_excluded_property_output_matches_xslt_and_golden():
    source = etree.parse(str(FIXTURE_DIR / "project.xml"))
    python_output = ProjectNormalizer(source).normalize()
    xslt_output = _xslt_output()
    golden_output = etree.parse(str(FIXTURE_DIR / "golden" / "project_normalized.xml"))

    for item_id, retained_names in RETAINED_PROPERTIES.items():
        python_item = python_output.xpath(".//Item[@id=$item_id]", item_id=item_id)[0]
        xslt_item = xslt_output.xpath(".//Item[@id=$item_id]", item_id=item_id)[0]
        golden_item = golden_output.xpath(".//Item[@id=$item_id]", item_id=item_id)[0]
        for item in (python_item, xslt_item, golden_item):
            assert not set(item.xpath("./Property/@name")) & set(EXCLUDED_NAMES)
        for name in retained_names:
            python_property = python_item.xpath("./Property[@name=$name]", name=name)[0]
            xslt_property = xslt_item.xpath("./Property[@name=$name]", name=name)[0]
            golden_property = golden_item.xpath("./Property[@name=$name]", name=name)[0]
            assert _canonical_xml(python_property) == _canonical_xml(xslt_property)
            assert _canonical_xml(xslt_property) == _canonical_xml(golden_property)


def test_all_six_excluded_property_names_are_omitted_from_id_items():
    root = (
        ProjectNormalizer(etree.parse(str(FIXTURE_DIR / "project.xml")))
        .normalize()
        .getroot()
    )

    for item_id in ("parent", "nested"):
        item = root.xpath(".//Item[@id=$item_id]", item_id=item_id)[0]
        assert not set(item.xpath("./Property/@name")) & set(EXCLUDED_NAMES)
        assert item.xpath("./Property[@name='DisplayOrder']")


def test_similar_property_names_and_properties_on_items_without_ids_remain():
    root = (
        ProjectNormalizer(etree.parse(str(FIXTURE_DIR / "project.xml")))
        .normalize()
        .getroot()
    )

    parent = root.xpath(".//Item[@id='parent']")[0]
    assert parent.xpath("./Property/@name") == [
        "RunStateValue",
        "DisplayOrderIndexes",
        "DisplayOrderGroupName",
        "PropertyMaskSetsExtra",
        "DataSources",
        "Definitions",
        "DisplayOrder",
    ]

    no_id_item = root.xpath(".//Item[@name='NoId']")[0]
    assert no_id_item.xpath("./Property[@name='Definition']/text()") == [
        "keep no-id definition"
    ]
    assert no_id_item.xpath("./Property[@name='RunState']/text()") == [
        "keep no-id runstate"
    ]

    empty_id_item = root.xpath(".//Item[@name='EmptyId']")[0]
    assert "id" in empty_id_item.attrib
    assert empty_id_item.get("id") == ""
    assert not empty_id_item.xpath("./Property[@name='Definition']")


def test_excluded_runstate_property_is_omitted_not_returned_as_empty_placeholder():
    normalizer = ProjectNormalizer(etree.parse(str(FIXTURE_DIR / "project.xml")))
    parent = etree.Element("Item", id="parent")
    property_node = etree.Element("Property", name="RunState")
    property_node.text = "running"

    for property_name in EXCLUDED_NAMES:
        property_node = etree.Element("Property", name=property_name)
        property_node.text = "source"
        assert normalizer.normalize_item_property(property_node, parent) is None

    no_id_parent = etree.Element("Item")
    assert normalizer.normalize_item_property(property_node, no_id_parent) is not None
