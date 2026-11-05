import json
import subprocess
import sys
from pathlib import Path

from lxml import etree

from ampla_security.testing.golden_validator import GoldenValidator

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "parity"
STYLESHEET_DIR = REPOSITORY_ROOT / "src" / "StyleSheets"


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ampla_security.cli.analyze", *arguments],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _canonical_html(path: Path) -> bytes:
    tree = etree.parse(str(path), etree.HTMLParser())
    for node in tree.iter():
        if node.text is not None and not node.text.strip():
            node.text = None
        if node.tail is not None and not node.tail.strip():
            node.tail = None
    return etree.tostring(tree, method="c14n")


def _normalize_line_endings(content: bytes) -> bytes:
    return content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def test_cli_runs_complete_pipeline_and_generates_all_outputs(tmp_path):
    output_dir = tmp_path / "chosen-output"
    result = _run_cli(
        "--project",
        str(FIXTURE_DIR / "project.xml"),
        "--authstore",
        str(FIXTURE_DIR / "authstore.xml"),
        "--output-dir",
        str(output_dir),
    )

    assert result.returncode == 0, result.stderr
    outputs = {
        "project_normalized": output_dir / "project.xml",
        "project_security": output_dir / "project.security.xml",
        "security_normalized": output_dir / "authstore.xml",
        "html_report": output_dir / "Project.Security.html",
        "roles_report": output_dir / "Project.Security.Roles.txt",
        "assignments_report": output_dir / "Project.Security.Assignments.txt",
    }
    assert all(path.is_file() for path in outputs.values())
    assert len(result.stdout.splitlines()) == len(outputs)

    validator = GoldenValidator(REPOSITORY_ROOT)
    for stage, filename in (
        ("project_normalized", "project_normalized.xml"),
        ("project_security", "project_security.xml"),
        ("authstore_normalized", "authstore_normalized.xml"),
    ):
        actual_stage = (
            "security_normalized" if stage == "authstore_normalized" else stage
        )
        comparison = validator.compare_normalized_xml(
            outputs[actual_stage],
            FIXTURE_DIR / "golden" / filename,
            stage=stage,
        )
        assert comparison["identical"] is True, comparison["diff"]

    normalized_security = etree.parse(str(outputs["security_normalized"]))
    html_xslt = etree.XSLT(etree.parse(str(STYLESHEET_DIR / "Document.Security.xslt")))
    expected_html = html_xslt(normalized_security)
    expected_html_path = tmp_path / "expected.html"
    expected_html_path.write_bytes(bytes(expected_html))
    assert _canonical_html(outputs["html_report"]) == _canonical_html(
        expected_html_path
    )

    text_xslt = etree.XSLT(
        etree.parse(str(STYLESHEET_DIR / "Document.Security.Text.xslt"))
    )
    for mode, output_key in (
        ("roles", "roles_report"),
        ("assignments", "assignments_report"),
    ):
        expected_text = text_xslt(normalized_security, mode=etree.XSLT.strparam(mode))
        assert _normalize_line_endings(outputs[output_key].read_bytes()) == (
            _normalize_line_endings(bytes(expected_text))
        )


def test_findings_are_opt_in_redacted_and_do_not_change_legacy_outputs(tmp_path):
    secret = "v1-1-private-db-password"
    project_tree = etree.parse(str(FIXTURE_DIR / "project.xml"))
    user = project_tree.xpath(".//Item[@id='user-alice']")[0]
    etree.SubElement(user, "Property", name="ConnectionString").text = (
        f"postgresql://scanner:{secret}@database.local/project"
    )
    project_input = tmp_path / "project-with-sensitive-value.xml"
    project_tree.write(
        str(project_input),
        encoding="utf-8",
        xml_declaration=True,
    )
    authstore = FIXTURE_DIR / "authstore.xml"
    baseline_dir = tmp_path / "baseline"
    findings_dir = tmp_path / "with-findings"

    baseline_result = _run_cli(
        "--project",
        str(project_input),
        "--authstore",
        str(authstore),
        "--output-dir",
        str(baseline_dir),
    )
    findings_result = _run_cli(
        "--project",
        str(project_input),
        "--authstore",
        str(authstore),
        "--output-dir",
        str(findings_dir),
        "--analyze-findings",
    )

    assert baseline_result.returncode == 0, baseline_result.stderr
    assert findings_result.returncode == 0, findings_result.stderr
    legacy_names = (
        "project.xml",
        "project.security.xml",
        "authstore.xml",
        "Project.Security.html",
        "Project.Security.Roles.txt",
        "Project.Security.Assignments.txt",
    )
    for filename in legacy_names:
        assert (baseline_dir / filename).read_bytes() == (
            findings_dir / filename
        ).read_bytes()

    assert not (baseline_dir / "findings.json").exists()
    findings_path = findings_dir / "findings.json"
    assert findings_path.is_file()
    findings_content = findings_path.read_text(encoding="utf-8")
    findings_payload = json.loads(findings_content)
    assert findings_payload["summary"]["total"] == 1
    assert findings_payload["findings"][0]["location"]["propertyName"] == (
        "ConnectionString"
    )
    assert secret not in findings_content
    assert "postgresql://scanner:" not in findings_content
    assert secret not in findings_result.stdout
    assert secret not in findings_result.stderr
    assert len(findings_result.stdout.splitlines()) == 7


def test_findings_cli_emits_empty_document_when_no_rule_matches(tmp_path):
    output_dir = tmp_path / "empty-findings"
    result = _run_cli(
        "--project",
        str(FIXTURE_DIR / "project.xml"),
        "--authstore",
        str(FIXTURE_DIR / "authstore.xml"),
        "--output-dir",
        str(output_dir),
        "--analyze-findings",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 0
    assert payload["findings"] == []


def test_cli_returns_nonzero_with_actionable_missing_input_error(tmp_path):
    missing_project = tmp_path / "missing.xml"
    result = _run_cli(
        "--project",
        str(missing_project),
        "--authstore",
        str(FIXTURE_DIR / "authstore.xml"),
        "--output-dir",
        str(tmp_path / "output"),
    )

    assert result.returncode != 0
    assert "Project input file does not exist" in result.stderr
    assert str(missing_project) in result.stderr


def test_cli_returns_nonzero_for_malformed_xml(tmp_path):
    malformed_project = tmp_path / "malformed.xml"
    malformed_project.write_text("<Project>", encoding="utf-8")
    result = _run_cli(
        "--project",
        str(malformed_project),
        "--authstore",
        str(FIXTURE_DIR / "authstore.xml"),
        "--output-dir",
        str(tmp_path / "output"),
    )

    assert result.returncode != 0
    assert "error:" in result.stderr
    assert "malformed.xml" in result.stderr


def test_cli_returns_nonzero_without_artifacts_for_invalid_authstore(tmp_path):
    invalid_authstore = tmp_path / "invalid-authstore.xml"
    invalid_authstore.write_text("<NotAuthStore/>", encoding="utf-8")
    output_dir = tmp_path / "output"
    result = _run_cli(
        "--project",
        str(FIXTURE_DIR / "project.xml"),
        "--authstore",
        str(invalid_authstore),
        "--output-dir",
        str(output_dir),
    )

    assert result.returncode != 0
    assert "Unsupported AuthStore root element" in result.stderr
    assert not output_dir.exists()


def test_cli_requires_both_inputs():
    result = _run_cli()

    assert result.returncode == 2
    assert "--project" in result.stderr
    assert "--authstore" in result.stderr
