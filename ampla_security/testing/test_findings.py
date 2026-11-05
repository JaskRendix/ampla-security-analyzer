import json

from lxml import etree

from ampla_security.engine.analyzer import analyze_project_findings
from ampla_security.engine.finding import Finding, serialize_findings


def _project(xml: str) -> etree._ElementTree:
    return etree.ElementTree(etree.fromstring(xml.encode("utf-8")))


def test_exposed_configuration_rule_detects_names_and_values_without_values():
    project = _project(
        """
        <Project>
          <Item id="alpha" name="Alpha">
            <Property name="Password">top-secret-password</Property>
            <Property name="Notes">Authorization: Bearer abc.def-123</Property>
            <Property name="Description">ordinary text</Property>
          </Item>
          <Item id="beta">
            <Property name="ConnectionString">postgresql://user:db-secret@host/db</Property>
          </Item>
        </Project>
        """
    )

    findings = analyze_project_findings(project)
    output = serialize_findings(findings)
    payload = json.loads(output)

    assert len(findings) == 3
    assert payload["summary"] == {
        "total": 3,
        "bySeverity": {"error": 0, "warning": 3, "info": 0},
    }
    assert {finding.rule_id for finding in findings} == {"exposed-configuration-data"}
    assert {finding.source_stage for finding in findings} == {"project-input"}
    assert {finding.location.property_name for finding in findings} == {
        "Password",
        "Notes",
        "ConnectionString",
    }
    for secret in (
        "top-secret-password",
        "abc.def-123",
        "db-secret",
        "postgresql://user:db-secret@host/db",
    ):
        assert secret not in output


def test_findings_json_order_and_ids_are_deterministic():
    source = """
    <Project>
      <Item id="zeta">
        <Property name="Password">secret-z</Property>
        <Property name="Password">another-secret-z</Property>
      </Item>
      <Item id="alpha">
        <Property name="Password">secret-a</Property>
      </Item>
    </Project>
    """

    first_findings = analyze_project_findings(_project(source))
    second_findings = analyze_project_findings(_project(source))
    first_output = serialize_findings(first_findings)
    second_output = serialize_findings(second_findings)
    payload = json.loads(first_output)

    assert first_output == second_output
    assert [finding["location"]["itemId"] for finding in payload["findings"]] == [
        "alpha",
        "zeta",
        "zeta",
    ]
    ids = [finding["id"] for finding in payload["findings"]]
    assert len(ids) == len(set(ids)) == 3


def test_finding_ids_do_not_depend_on_detected_value():
    def finding_for(value: str) -> Finding:
        project = _project(
            "<Project><Item id='item-1'>"
            f"<Property name='Password'>{value}</Property>"
            "</Item></Project>"
        )
        return analyze_project_findings(project)[0]

    first = finding_for("first-secret-value")
    second = finding_for("different-secret-value")

    assert first.id == second.id
    assert "first-secret-value" not in serialize_findings([first])
    assert "different-secret-value" not in serialize_findings([second])


def test_empty_findings_serialize_with_zero_counts():
    payload = json.loads(serialize_findings([]))

    assert payload == {
        "schemaVersion": "1.0",
        "summary": {
            "total": 0,
            "bySeverity": {"error": 0, "warning": 0, "info": 0},
        },
        "findings": [],
    }
