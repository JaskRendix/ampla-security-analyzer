from pathlib import Path

import pytest
from lxml import etree

from ampla_security.normalization.project_normalizer import ProjectNormalizer

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "translations"
PROJECT = FIXTURE_DIR / "project.xml"
LANGUAGE = FIXTURE_DIR / "language.html"
GOLDEN = FIXTURE_DIR / "golden" / "normalized_project.xml"
STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Project.Normalize.xslt"
)


def _canonical_xml(tree: etree._ElementTree) -> bytes:
    root = tree.getroot()
    for element in root.xpath(".//*[@hash]"):
        element.attrib.pop("hash", None)
    return etree.tostring(root, method="c14n", with_comments=True)


def _xslt_output(with_language: bool) -> etree._ElementTree:
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    parameters = {}
    if with_language:
        parameters["language"] = etree.XSLT.strparam(LANGUAGE.resolve().as_uri())
    result = transform(etree.parse(str(PROJECT)), **parameters)
    return etree.ElementTree(etree.fromstring(etree.tostring(result)))


def test_translation_output_matches_live_xslt_and_golden():
    source = etree.parse(str(PROJECT))
    python_output = ProjectNormalizer(source, language_document=LANGUAGE).normalize()
    xslt_output = _xslt_output(with_language=True)
    golden_output = etree.parse(str(GOLDEN))

    assert _canonical_xml(python_output) == _canonical_xml(xslt_output)
    assert _canonical_xml(xslt_output) == _canonical_xml(golden_output)


def test_translations_apply_to_items_class_definitions_and_matrix_inputs():
    output = ProjectNormalizer(
        etree.parse(str(PROJECT)), language_document=LANGUAGE
    ).normalize()

    assert output.xpath(".//Item[@id='pump']/@translation") == ["Pompa centrifuga"]
    assert output.xpath(".//Item[@id='machine-class']/@translation") == ["Macchina"]
    assert output.xpath(".//Item[@id='drive-class']/@translation") == ["Trasmissione"]
    assert output.xpath(".//Item[@id='matrix']/Input/@translation") == ["Calcolato"]


def test_equal_empty_missing_and_duplicate_translations_follow_xslt_rules():
    output = ProjectNormalizer(
        etree.parse(str(PROJECT)), language_document=LANGUAGE
    ).normalize()

    assert output.xpath(".//Item[@id='plain']/@translation") == []
    assert output.xpath(".//Item[@id='untranslated']/@translation") == []
    assert output.xpath(".//Item[@id='empty-translation']/@translation") == []
    assert output.xpath(".//Item[@id='pump']/@translation") == ["Pompa centrifuga"]


def test_no_language_document_preserves_untranslated_output():
    python_output = ProjectNormalizer(etree.parse(str(PROJECT))).normalize()
    xslt_output = _xslt_output(with_language=False)

    assert _canonical_xml(python_output) == _canonical_xml(xslt_output)
    assert not python_output.xpath(".//@translation")


def test_language_tree_and_element_inputs_are_supported():
    language_tree = etree.parse(str(LANGUAGE))
    expected = ProjectNormalizer(
        etree.parse(str(PROJECT)), language_document=LANGUAGE
    ).normalize()

    for language_document in (language_tree, language_tree.getroot()):
        actual = ProjectNormalizer(
            etree.parse(str(PROJECT)), language_document=language_document
        ).normalize()
        assert _canonical_xml(actual) == _canonical_xml(expected)


def test_missing_supplied_language_document_raises_file_error(tmp_path):
    with pytest.raises(OSError, match="missing-language.html"):
        ProjectNormalizer(
            etree.parse(str(PROJECT)),
            language_document=tmp_path / "missing-language.html",
        )
