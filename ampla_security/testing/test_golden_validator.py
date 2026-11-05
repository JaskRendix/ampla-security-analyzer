import subprocess
import sys
from pathlib import Path

import pytest
from lxml import etree

from ampla_security.testing.golden_validator import (
    PIPELINE_STAGES,
    GoldenValidator,
    ParityValidationError,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "parity"


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_end_to_end_pipeline_matches_xslt_and_checked_in_goldens(tmp_path):
    validator = GoldenValidator(REPOSITORY_ROOT)
    validator.working_dir = tmp_path / "working"

    results = validator.validate_pipeline(
        FIXTURE_DIR / "project.xml",
        FIXTURE_DIR / "authstore.xml",
    )

    assert results["passed"] is True
    assert tuple(results["comparisons"]) == PIPELINE_STAGES
    assert {
        stage: comparison["identical"]
        for stage, comparison in results["comparisons"].items()
    } == {stage: True for stage in PIPELINE_STAGES}
    assert set(results["python_outputs"]) == set(PIPELINE_STAGES)
    assert set(results["xslt_outputs"]) == set(PIPELINE_STAGES)
    assert results["xslt_runtime"]["processor"] == "lxml/libxslt"
    assert set(results["xslt_runtime"]) == {
        "processor",
        "lxml",
        "libxml",
        "libxslt",
    }
    assert all(
        isinstance(results["xslt_runtime"][version], list)
        and all(
            isinstance(component, int) for component in results["xslt_runtime"][version]
        )
        for version in ("lxml", "libxml", "libxslt")
    )
    assert results["canonicalization"] == {
        "generated_hashes": (
            "Compare @hash presence and location on normalized Item nodes, extracted "
            "User/Scope nodes, and normalized Security User nodes, but ignore values "
            "because Python SHA-1 hashes and XSLT generate-id() values are generated "
            "by different mechanisms."
        ),
        "translation_count_comment": (
            "Ignore only the top-level XSLT comment matching '<integer> Translations' "
            "in project_normalized. It is stylesheet diagnostic metadata; all other "
            "comments and XML content remain part of the comparison."
        ),
        "formatting_whitespace": (
            "Ignore whitespace-only indentation only in known element-only containers "
            "and around the nested Identity element inside Property[@name='Identity']. "
            "Preserve all other text, including whitespace in property and identity values."
        ),
        "other_differences": (
            "Attribute order is canonicalized. Element order, names, attributes, "
            "significant text, and comments are compared."
        ),
    }

    for stage in PIPELINE_STAGES:
        expected = FIXTURE_DIR / "golden" / f"{stage}.xml"
        actual = results["xslt_outputs"][stage]
        comparison = validator.compare_normalized_xml(actual, expected, stage)
        assert comparison["identical"] is True, comparison["diff"]


def test_canonicalization_ignores_only_justified_generated_hashes(tmp_path):
    validator = GoldenValidator(REPOSITORY_ROOT)
    python_xml = _write(
        tmp_path / "python.xml",
        '<Project><Item id="one" hash="python-hash"/></Project>',
    )
    xslt_xml = _write(
        tmp_path / "xslt.xml",
        '<Project><Item id="one" hash="id1"/></Project>',
    )
    assert (
        validator.compare_normalized_xml(python_xml, xslt_xml, "project_normalized")[
            "identical"
        ]
        is True
    )

    python_xml.write_text(
        '<Project><Item id="one"><Property hash="python-hash"/></Item></Project>',
        encoding="utf-8",
    )
    xslt_xml.write_text(
        '<Project><Item id="one"><Property hash="id1"/></Item></Project>',
        encoding="utf-8",
    )
    comparison = validator.compare_normalized_xml(
        python_xml, xslt_xml, "project_normalized"
    )
    assert comparison["identical"] is False
    assert 'hash="id1"' in comparison["diff"]


def test_generated_hash_value_may_differ_but_attribute_must_be_present(tmp_path):
    validator = GoldenValidator(REPOSITORY_ROOT)
    python_xml = _write(
        tmp_path / "python.xml",
        '<Project><Item id="one" hash="python-hash"/></Project>',
    )
    xslt_xml = _write(
        tmp_path / "xslt.xml",
        '<Project><Item id="one"/></Project>',
    )

    comparison = validator.compare_normalized_xml(
        python_xml, xslt_xml, "project_normalized"
    )
    assert comparison["identical"] is False
    assert comparison["generated_hash_presence_matches"] is False
    assert "generated hash attributes are missing or extra" in comparison["summary"]


def test_canonicalization_preserves_text_whitespace_and_other_comments(tmp_path):
    validator = GoldenValidator(REPOSITORY_ROOT)
    python_xml = _write(
        tmp_path / "python.xml",
        "<Project><!--custom--><Property> value </Property></Project>",
    )
    xslt_xml = _write(
        tmp_path / "xslt.xml",
        "<!--0 Translations--><Project><!--custom--><Property> value </Property></Project>",
    )
    assert (
        validator.compare_normalized_xml(python_xml, xslt_xml, "project_normalized")[
            "identical"
        ]
        is True
    )

    xslt_xml.write_text(
        "<!--unexpected--><Project><!--custom--><Property> value  </Property></Project>",
        encoding="utf-8",
    )
    comparison = validator.compare_normalized_xml(
        python_xml, xslt_xml, "project_normalized"
    )
    assert comparison["identical"] is False
    assert "unexpected" in comparison["diff"]
    assert "value  " in comparison["diff"]


def test_validator_rejects_missing_and_extra_output_stages():
    with pytest.raises(ParityValidationError, match="missing stages: project_security"):
        GoldenValidator._validate_output_set(
            "Python",
            {
                "project_normalized": "project.xml",
                "authstore_normalized": "authstore.xml",
            },
        )

    with pytest.raises(ParityValidationError, match="unexpected stages: report"):
        GoldenValidator._validate_output_set(
            "XSLT",
            {
                **{stage: f"{stage}.xml" for stage in PIPELINE_STAGES},
                "report": "report.html",
            },
        )


def test_pipeline_fails_actionably_when_a_required_output_file_is_absent(tmp_path):
    validator = GoldenValidator(REPOSITORY_ROOT)
    outputs = {stage: str(tmp_path / f"{stage}.xml") for stage in PIPELINE_STAGES}
    for stage, output in outputs.items():
        if stage != "project_security":
            Path(output).write_text("<Security/>", encoding="utf-8")

    validator.run_python_pipeline = lambda *_: outputs
    validator.run_xslt_pipeline = lambda *_: outputs
    with pytest.raises(
        ParityValidationError,
        match="Python pipeline did not produce required stage 'project_security'",
    ):
        validator.validate_pipeline("project.xml", "authstore.xml")


def test_pipeline_raises_on_unhandled_structural_differences(tmp_path):
    validator = GoldenValidator(REPOSITORY_ROOT)
    python_outputs = {}
    xslt_outputs = {}
    for stage in PIPELINE_STAGES:
        python_content = (
            "<Project><Item id='one'/></Project>"
            if stage == "project_normalized"
            else "<Security/>"
        )
        xslt_content = (
            "<Project><Item id='one'/><Unexpected/></Project>"
            if stage == "project_normalized"
            else "<Security/>"
        )
        python_outputs[stage] = str(
            _write(tmp_path / f"python_{stage}.xml", python_content)
        )
        xslt_outputs[stage] = str(_write(tmp_path / f"xslt_{stage}.xml", xslt_content))

    validator.run_python_pipeline = lambda *_: python_outputs
    validator.run_xslt_pipeline = lambda *_: xslt_outputs
    with pytest.raises(ParityValidationError, match="project_normalized") as error:
        validator.validate_pipeline("project.xml", "authstore.xml")

    assert error.value.results["passed"] is False
    project_comparison = error.value.results["comparisons"]["project_normalized"]
    assert project_comparison["identical"] is False
    assert "Unexpected" in project_comparison["diff"]


def test_validator_confirms_default_display_order_matches_xslt(tmp_path):
    project_tree = etree.parse(str(FIXTURE_DIR / "project.xml"))
    for item in project_tree.xpath("//Item[@id='site' or @id='area']"):
        for display_order in item.xpath("./Property[@name='DisplayOrder']"):
            item.remove(display_order)
    project_input = tmp_path / "project_without_display_orders.xml"
    project_tree.write(str(project_input), encoding="utf-8")

    validator = GoldenValidator(REPOSITORY_ROOT)
    validator.working_dir = tmp_path / "working"
    results = validator.validate_pipeline(project_input, FIXTURE_DIR / "authstore.xml")

    project_comparison = results["comparisons"]["project_normalized"]
    assert results["passed"] is True
    assert project_comparison["identical"] is True


def test_module_cli_runs_the_complete_parity_pipeline(tmp_path):
    command = [
        sys.executable,
        "-m",
        "ampla_security.testing.golden_validator",
        "--project",
        str(FIXTURE_DIR / "project.xml"),
        "--authstore",
        str(FIXTURE_DIR / "authstore.xml"),
        "--project-root",
        str(REPOSITORY_ROOT),
        "--working-dir",
        str(tmp_path / "working"),
    ]
    result = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "PASS project_normalized:" in result.stdout
    assert "PASS project_security:" in result.stdout
    assert "PASS authstore_normalized:" in result.stdout
    assert "Python and XSLT outputs match for all required stages." in result.stdout
