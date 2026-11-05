from pathlib import Path

from lxml import etree

from ampla_security.normalization.project_normalizer import ProjectNormalizer

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "selective_copy"
GOLDEN = FIXTURE_DIR / "golden" / "normalized_project.xml"
STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Project.Normalize.xslt"
)


def _without_generated_hashes(tree: etree._ElementTree) -> bytes:
    root = tree.getroot()
    for element in root.xpath(".//Item[@hash] | .//Input[@hash]"):
        element.attrib.pop("hash", None)
    for element in root.iter():
        if element.text == "":
            element.text = None
    return etree.tostring(root, method="c14n", with_comments=True)


def _xslt_output() -> etree._ElementTree:
    source = etree.parse(str(FIXTURE_DIR / "project.xml"))
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    result = transform(source)
    return etree.ElementTree(etree.fromstring(etree.tostring(result)))


def test_selective_item_and_property_copy_matches_xslt():
    source = etree.parse(str(FIXTURE_DIR / "project.xml"))
    python_output = ProjectNormalizer(source).normalize()
    xslt_output = _xslt_output()
    golden_output = etree.parse(str(GOLDEN))

    assert _without_generated_hashes(python_output) == _without_generated_hashes(
        xslt_output
    )
    assert _without_generated_hashes(xslt_output) == _without_generated_hashes(
        golden_output
    )


def test_identified_items_and_ordinary_properties_drop_unselected_attributes():
    root = ProjectNormalizer(etree.parse(str(FIXTURE_DIR / "project.xml"))).normalize()
    parent = root.xpath(".//Item[@id='parent']")[0]
    child = root.xpath(".//Item[@id='child']")[0]
    grandchild = root.xpath(".//Item[@id='grandchild']")[0]

    assert set(parent.attrib) == {"hash", "id", "name", "type", "fullName"}
    assert set(child.attrib) == {"hash", "id", "name", "type", "fullName"}
    assert set(grandchild.attrib) == {"hash", "id", "name", "type", "fullName"}
    mixed = parent.xpath("./Property[@name='Mixed']")[0]
    assert mixed.attrib == {"id": "property-id", "name": "Mixed"}
    assert mixed.xpath("./Child/@extra") == ["keep-nested-attribute"]
    assert mixed.xpath("./Child/comment()")
    assert parent.xpath(
        "./Property[@name='ClassAssociation']/ItemLink[@targetID='missing-class' and @absolutePath='']"
    )


def test_identified_items_omit_unselected_content_but_no_id_items_are_copied():
    root = ProjectNormalizer(etree.parse(str(FIXTURE_DIR / "project.xml"))).normalize()
    parent = root.xpath(".//Item[@id='parent']")[0]
    no_id = root.xpath(".//Item[@name='NoId']")[0]

    assert parent.text is None
    assert not parent.xpath("./Unexpected")
    assert not parent.xpath("./comment()")
    assert no_id.get("extra") == "preserve-no-id-attribute"
    assert no_id.xpath("./Unexpected/Inner[text()='keep this']")
    assert no_id.xpath("./comment()[contains(., 'Keep no-id comment')]")


def test_specialized_item_reconstruction_keeps_xslt_attribute_and_child_order():
    root = ProjectNormalizer(etree.parse(str(FIXTURE_DIR / "project.xml"))).normalize()
    user = root.xpath(".//Item[@id='user']")[0]
    resolver = root.xpath(".//Item[@id='resolver']")[0]
    equipment_template = root.xpath(".//Item[@id='equipment-template']")[0]

    assert set(user.attrib) == {"hash", "id", "name", "type", "fullName"}
    assert [child.get("name") for child in user] == [
        "DisplayOrder",
        "Authentication",
        "UserChild",
    ]
    assert user.xpath("./Property[@name='Authentication']/text()") == [
        "WindowsIntegrated"
    ]
    assert set(resolver.attrib) == {"hash", "id", "name", "type", "fullName"}
    assert [child.get("name") for child in resolver] == [
        "Action",
        "DisplayOrder",
        "ResolverOperation",
        "ResolverChild",
    ]
    assert resolver.xpath("./Property[@name='ResolverOperation']/text()") == ["Sum"]
    target_class = equipment_template.xpath("./Property[@name='TargetEquipmentClass']")[
        0
    ]
    assert target_class.attrib == {
        "name": "TargetEquipmentClass",
        "classDefinitionId": "equipment-class",
        "extra": "preserved-by-special-template",
        "class": "true",
    }
    assert target_class.xpath(
        "./ItemLink[@targetID='equipment-class' and @absolutePath='Equipment']"
    )
    assert not target_class.xpath("./Unexpected")
