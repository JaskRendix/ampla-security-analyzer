from __future__ import annotations

import argparse

from ampla_security.engine import rules  # noqa: F401
from ampla_security.engine.context import AnalysisContext
from ampla_security.engine.dispatcher import RuleDispatcher
from ampla_security.engine.registry import registry
from ampla_security.normalization.authstore_normalizer import AuthstoreNormalizer
from ampla_security.normalization.document_normalizer import DocumentNormalizer
from ampla_security.normalization.project_normalizer import ProjectNormalizer
from ampla_security.reporting.html_reporter import HtmlReporter
from ampla_security.xml.loader import load_xml


def main() -> None:
    parser = argparse.ArgumentParser(description="Ampla Security Analysis Tool")
    parser.add_argument("input", help="Input XML file")
    parser.add_argument("type", choices=["project", "authstore", "document"])
    args = parser.parse_args()

    tree = load_xml(args.input)

    if args.type == "project":
        normalizer = ProjectNormalizer(tree)
    elif args.type == "authstore":
        normalizer = AuthstoreNormalizer(tree)
    else:
        normalizer = DocumentNormalizer(tree)

    normalized = normalizer.normalize()
    context = AnalysisContext(normalized)
    dispatcher = RuleDispatcher(registry, context)

    findings = dispatcher.run(args.type)
    reporter = HtmlReporter(findings)
    reporter.generate("security_report.html")
