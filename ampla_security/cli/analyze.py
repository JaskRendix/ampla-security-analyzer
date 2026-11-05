from __future__ import annotations

import argparse
import sys
from pathlib import Path

from lxml import etree

from ampla_security.normalization.authstore_normalizer import AuthstoreNormalizer
from ampla_security.normalization.project_normalizer import ProjectNormalizer
from ampla_security.normalization.project_security_extractor import (
    ProjectSecurityExtractor,
)
from ampla_security.reporting.html_reporter import HtmlReporter
from ampla_security.reporting.security_text_reporter import SecurityTextReporter
from ampla_security.xml.loader import load_xml


def run_pipeline(
    project_path: str | Path,
    authstore_path: str | Path,
    output_dir: str | Path,
) -> dict[str, Path]:
    """Run normalization, security extraction, and all legacy report generation."""
    project_input = Path(project_path)
    authstore_input = Path(authstore_path)
    output_directory = Path(output_dir)

    for label, path in (
        ("Project", project_input),
        ("AuthStore", authstore_input),
    ):
        if not path.is_file():
            raise FileNotFoundError(f"{label} input file does not exist: {path}")

    project_tree = load_xml(project_input)
    authstore_tree = load_xml(authstore_input)
    normalized_project = ProjectNormalizer(project_tree).normalize()
    project_security = ProjectSecurityExtractor(normalized_project).extract()
    authstore_normalizer = AuthstoreNormalizer(authstore_tree)
    authstore_normalizer.set_project_security(project_security)
    normalized_security = authstore_normalizer.normalize()

    html_report = HtmlReporter(normalized_security).render()
    text_reporter = SecurityTextReporter(normalized_security)
    roles_report = text_reporter.render_roles()
    assignments_report = text_reporter.render_assignments()

    output_directory.mkdir(parents=True, exist_ok=True)
    outputs = {
        "project_normalized": output_directory / "project.xml",
        "project_security": output_directory / "project.security.xml",
        "security_normalized": output_directory / "authstore.xml",
        "html_report": output_directory / "Project.Security.html",
        "roles_report": output_directory / "Project.Security.Roles.txt",
        "assignments_report": output_directory / "Project.Security.Assignments.txt",
    }
    normalized_project.write(
        str(outputs["project_normalized"]),
        encoding="UTF-8",
        xml_declaration=True,
        pretty_print=True,
    )
    project_security.write(
        str(outputs["project_security"]),
        encoding="UTF-8",
        xml_declaration=True,
        pretty_print=True,
    )
    normalized_security.write(
        str(outputs["security_normalized"]),
        encoding="UTF-8",
        xml_declaration=True,
        pretty_print=True,
    )
    outputs["html_report"].write_text(html_report, encoding="utf-8")
    outputs["roles_report"].write_bytes(roles_report.encode("utf-8"))
    outputs["assignments_report"].write_bytes(assignments_report.encode("utf-8"))
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ampla Security Analysis Tool")
    parser.add_argument("--project", required=True, help="Project XML input")
    parser.add_argument("--authstore", required=True, help="AuthStore XML input")
    parser.add_argument(
        "--output-dir",
        default="Output",
        help="Directory for normalized XML and reports (default: Output)",
    )
    args = parser.parse_args(argv)

    try:
        outputs = run_pipeline(args.project, args.authstore, args.output_dir)
    except (OSError, etree.XMLSyntaxError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    for label, path in outputs.items():
        print(f"{label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
