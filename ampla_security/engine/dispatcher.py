from __future__ import annotations

from collections.abc import Iterable
from typing import Any


class RuleDispatcher:
    """
    Executes rules using XSLT-style match precedence:
    1. Highest priority wins
    2. More specific XPath patterns win
    3. Mode separation (project/document/text)
    4. Fallback rules apply last
    """

    def __init__(self, registry: Any, context: Any) -> None:
        self.registry = registry
        self.context = context

    def run(self, category: str) -> list[Any]:
        """
        Execute all rules for a given category using XSLT precedence.
        """
        rules = self.registry.get_rules(category)
        ordered = self._order_rules_by_precedence(rules)

        findings: list[Any] = []
        for rule in ordered:
            result = rule.apply(self.context)
            if result is None:
                continue
            if isinstance(result, list):
                findings.extend(result)
            else:
                findings.append(result)

        return findings

    def _order_rules_by_precedence(self, rules: Iterable[Any]) -> list[Any]:
        """
        Sort rules using XSLT precedence rules:
        1. Explicit priority (if rule defines .priority)
        2. Pattern specificity (XPath complexity)
        3. Declaration order (fallback)
        """
        return sorted(
            rules,
            key=lambda r: (
                -self._get_priority(r),
                -self._pattern_specificity(r),
                self._declaration_order(r),
            ),
        )

    def _get_priority(self, rule: Any) -> int:
        """
        XSLT: <xsl:template priority="X">
        Python: rule.priority (optional)
        """
        return getattr(rule, "priority", 0)

    def _pattern_specificity(self, rule: Any) -> int:
        """
        Approximate XPath specificity:
        - More steps = more specific
        - Predicates increase specificity
        - Attribute tests increase specificity
        """
        pattern: str | None = getattr(rule, "match", None)
        if not pattern:
            return 0

        score = 0
        score += pattern.count("/") * 2
        score += pattern.count("[") * 3
        score += pattern.count("@") * 4

        return score

    def _declaration_order(self, rule: Any) -> int:
        """
        XSLT: later templates override earlier ones only if priority ties.
        Python: use class definition order.
        """
        return getattr(rule, "__definition_index__", 0)
