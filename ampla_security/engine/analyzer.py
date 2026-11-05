from __future__ import annotations

from lxml.etree import _ElementTree

from ampla_security.engine.context import AnalysisContext
from ampla_security.engine.dispatcher import RuleDispatcher
from ampla_security.engine.finding import Finding
from ampla_security.engine.registry import RuleRegistry
from ampla_security.engine.rules.project_rules import ExposedConfigurationDataRule


def analyze_project_findings(project_tree: _ElementTree) -> list[Finding]:
    """Run only the opt-in configuration exposure rule on source project XML."""
    registry = RuleRegistry()
    registry.register(ExposedConfigurationDataRule())
    context = AnalysisContext(project_tree)
    results = RuleDispatcher(registry, context).run("project")
    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, Finding):
            raise TypeError("Exposed configuration rule returned an invalid finding")
        findings.append(result)
    return findings
