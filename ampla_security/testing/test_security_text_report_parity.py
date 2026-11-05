from pathlib import Path

import pytest
from lxml import etree

from ampla_security.reporting.security_text_reporter import SecurityTextReporter

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "security_report"
STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Document.Security.Text.xslt"
)


def _render_python(output_dir: Path) -> tuple[Path, Path]:
    security_tree = etree.parse(str(FIXTURE_DIR / "security.xml"))
    roles_path = output_dir / "Project.Security.Roles.txt"
    assignments_path = output_dir / "Project.Security.Assignments.txt"
    SecurityTextReporter(security_tree).generate(roles_path, assignments_path)
    return roles_path, assignments_path


def _render_xslt(mode: str, output_path: Path) -> bytes:
    security_tree = etree.parse(str(FIXTURE_DIR / "security.xml"))
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    result = transform(security_tree, mode=etree.XSLT.strparam(mode))
    output_path.write_bytes(bytes(result))
    return bytes(result)


def _normalize_line_endings(content: bytes) -> bytes:
    return content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def test_roles_report_matches_xslt_and_golden(tmp_path):
    roles_path, _ = _render_python(tmp_path)
    xslt_path = tmp_path / "xslt_roles.txt"
    xslt_output = _render_xslt("roles", xslt_path)
    golden_path = FIXTURE_DIR / "golden" / "Project.Security.Roles.txt"

    python_output = roles_path.read_bytes()
    golden_output = golden_path.read_bytes()
    assert _normalize_line_endings(python_output) == _normalize_line_endings(
        xslt_output
    )
    assert _normalize_line_endings(xslt_output) == _normalize_line_endings(
        golden_output
    )
    assert python_output.startswith(b"\r\n========================================\r\n")
    assert b"Role: 'Administrator'" in python_output
    assert python_output.index(b"Role: 'Administrator'") < python_output.index(
        b"Role: 'Reader & Reviewer'"
    )
    assert python_output.index(b"+  Operation: 'Write'") < python_output.index(
        b"+  Operation: 'Read & Review'"
    )


def test_assignments_report_matches_xslt_and_golden(tmp_path):
    _, assignments_path = _render_python(tmp_path)
    xslt_path = tmp_path / "xslt_assignments.txt"
    xslt_output = _render_xslt("assignments", xslt_path)
    golden_path = FIXTURE_DIR / "golden" / "Project.Security.Assignments.txt"

    python_output = assignments_path.read_bytes()
    golden_output = golden_path.read_bytes()
    assert _normalize_line_endings(python_output) == _normalize_line_endings(
        xslt_output
    )
    assert _normalize_line_endings(xslt_output) == _normalize_line_endings(
        golden_output
    )
    assert python_output.startswith(b"\r\n========================================\r\n")
    assert (
        python_output.index(b"User: 'Alice & Co'")
        < python_output.index(b"User: 'Bob'")
        < python_output.index(b"User: 'Cathy <Guest> Caf\xc3\xa9'")
    )
    assert b"      Authentication = WindowsIntegrated\r\n" in python_output
    assert b"      Identity = DOMAIN\\alice & Co\r\n" in python_output
    assert b"      Authentication = Basic <token>\r\n" in python_output
    assert b"      Identity = CITEC\\cathy & guest\r\n" in python_output
    assert b"SecurityID" not in python_output
    assert b"S-1-9-cathy" not in python_output
    assert b"+  [Denied]\r\n   Admin Zone\r\n   Zeta <Area>" in python_output
    assert b"+  Role: 'Reader & Reviewer'\r\n   Deleted <Scope>\r\n" in python_output


def test_generate_creates_both_legacy_report_files(tmp_path):
    roles_path, assignments_path = _render_python(tmp_path / "reports")

    assert roles_path.name == "Project.Security.Roles.txt"
    assert assignments_path.name == "Project.Security.Assignments.txt"
    assert roles_path.is_file()
    assert assignments_path.is_file()


def test_security_text_report_rejects_non_security_xml():
    with pytest.raises(ValueError, match="Security text report input"):
        SecurityTextReporter(etree.Element("Project"))
