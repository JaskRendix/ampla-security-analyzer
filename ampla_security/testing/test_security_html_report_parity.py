from pathlib import Path

import pytest
from lxml import etree

from ampla_security.reporting.html_reporter import HtmlReporter

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "security_report"
STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Document.Security.xslt"
)


def _render_python(output_path: Path) -> str:
    security_tree = etree.parse(str(FIXTURE_DIR / "security.xml"))
    HtmlReporter(security_tree).generate(output_path)
    return output_path.read_text(encoding="utf-8")


def _render_xslt(output_path: Path) -> str:
    security_tree = etree.parse(str(FIXTURE_DIR / "security.xml"))
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    result = transform(security_tree)
    output_path.write_bytes(bytes(result))
    return output_path.read_text(encoding="utf-8")


def _canonical_html(path: Path) -> bytes:
    tree = etree.parse(str(path), etree.HTMLParser())
    for node in tree.iter():
        if node.text is not None and not node.text.strip():
            node.text = None
        if node.tail is not None and not node.tail.strip():
            node.tail = None
    return etree.tostring(tree, method="c14n")


def test_security_report_matches_xslt_and_checked_in_golden(tmp_path):
    python_path = tmp_path / "python_security_report.html"
    xslt_path = tmp_path / "xslt_security_report.html"
    python_html = _render_python(python_path)
    _render_xslt(xslt_path)

    assert _canonical_html(python_path) == _canonical_html(xslt_path)
    assert _canonical_html(xslt_path) == _canonical_html(
        FIXTURE_DIR / "golden" / "security_report.html"
    )
    assert python_html.startswith(
        '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"'
    )
    assert "&lt;data&gt;" in python_html
    assert "&amp;" in python_html
    assert "&quot;read&quot;" in python_html
    assert "Café".encode("utf-8") in python_path.read_bytes()


def test_report_includes_sections_role_matrix_scope_tables_and_user_details(
    tmp_path,
):
    output_path = tmp_path / "security_report.html"
    _render_python(output_path)
    tree = etree.parse(str(output_path), etree.HTMLParser())
    root = tree.getroot()

    assert root.xpath("//h2/text()") == [
        "Roles",
        "Security Scopes",
        "Errors in Security Scopes",
        "User Role Assignments",
    ]
    assert root.xpath("//a/@name") == ["roles", "scopes", "users"]
    assert root.xpath("//title/text()") == ["Ampla Project Summary - Security"]
    assert root.xpath("//link/@href") == ["css/security.css"]
    assert root.xpath("//meta[@http-equiv='Content-Type']/@content") == [
        "text/html; charset=UTF-8"
    ]
    tables = root.xpath("//table")
    assert len(tables) == 4

    role_rows = tables[0].xpath("./tbody/tr")
    assert role_rows[0].xpath("./th/span/text()") == [
        "Reader & Reviewer",
        "Administrator",
    ]
    assert role_rows[1].xpath("./td[@class='center allowed']/span/text()") == ["Y"]
    assert role_rows[1].xpath("./td[@class='center denied']/span/text()") == ["."]
    assert role_rows[2].xpath("./td[@class='center denied']/span/text()") == ["."]
    assert role_rows[2].xpath("./td[@class='center allowed']/span/text()") == ["Y"]

    valid_scope_rows = tables[1].xpath("./tbody/tr[position() > 1]")
    assert [row.xpath("./td[1]/span/text()")[0] for row in valid_scope_rows] == [
        "Ops & Reporting",
        "Zeta <Area>",
        "Admin Zone",
    ]
    assert valid_scope_rows[0].xpath(
        "./td[@class='allowed']//li/span[@class='user' or @class='warning user']/text()"
    ) == ["Alice & Co", "unknown unknown user"]

    invalid_scope_row = tables[2].xpath("./tbody/tr[position() = 2]")[0]
    assert invalid_scope_row.xpath("./td[1]/span[@class='warning']/text()") == [
        "Warning: Scope <removed> & unavailable"
    ]
    assert invalid_scope_row.xpath(
        "./td[@class='allowed']//span[@class='user']/text()"
    ) == ["Alice & Co"]

    user_rows = tables[3].xpath("./tbody/tr[position() > 2]")
    assert [row.xpath("./td[1]/span[1]/text()")[0] for row in user_rows] == [
        "Cathy <Guest> Café",
        "Alice & Co",
        "Bob",
    ]
    cathy_cells = user_rows[0].xpath("./td")
    assert cathy_cells[0].xpath("./span/text()") == [
        "Cathy <Guest> Café",
        "Account & identity need review",
    ]
    assert [str(cell.xpath("string(.)")) for cell in cathy_cells[1:4]] == [
        "Basic <token>",
        "S-1-9-cathy",
        r"CITEC\cathy & guest",
    ]
    assert cathy_cells[4].get("class") == "denied"
    assert [
        item.xpath("./span[1]/text()")[0] for item in cathy_cells[5].xpath("./ul/li")
    ] == ["Admin Zone", "Ops & Reporting", "Zeta <Area>"]
    assert cathy_cells[6].get("class") == ""

    alice_cells = user_rows[1].xpath("./td")
    assert alice_cells[4].get("class") == "allowed"
    assert [
        item.xpath("./span[1]/text()")[0] for item in alice_cells[4].xpath("./ul/li")
    ] == ["Ops & Reporting"]
    assert [
        item.xpath("./span[1]/text()")[0] for item in alice_cells[5].xpath("./ul/li")
    ] == ["Admin Zone", "Zeta <Area>"]
    assert alice_cells[6].xpath("./ul/li/span[@class='scope warning']/text()") == [
        "Deleted <Scope>"
    ]


def test_security_report_rejects_non_security_xml():
    with pytest.raises(ValueError, match="Security root"):
        HtmlReporter(etree.Element("Project"))


def test_report_omits_invalid_section_when_there_are_no_invalid_scopes(tmp_path):
    security = etree.fromstring(
        b"<Security><Operations/><RoleDefinitions/><Scopes>"
        b'<Scope name="Global" valid="Default scope"/></Scopes><Users>'
        b'<User id="alice" name="Alice"/></Users></Security>'
    )
    output_path = tmp_path / "security_report.html"
    HtmlReporter(security).generate(output_path)
    root = etree.parse(str(output_path), etree.HTMLParser()).getroot()

    assert root.xpath("//h2/text()") == [
        "Roles",
        "Security Scopes",
        "User Role Assignments",
    ]
    assert len(root.xpath("//table")) == 3
    assert root.xpath("//table[last()]/tbody/tr[2]/th/text()") == [
        "Allowed",
        "Denied",
    ]
