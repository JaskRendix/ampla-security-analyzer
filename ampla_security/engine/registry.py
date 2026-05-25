from __future__ import annotations

from typing import Any


class RuleRegistry:
    """
    Stores all registered security rules.
    """

    def __init__(self) -> None:
        self.rules: list[Any] = []
        self._definition_counter: int = 0

    def register(self, rule: Any) -> None:
        setattr(rule, "__definition_index__", self._definition_counter)
        self._definition_counter += 1
        self.rules.append(rule)

    def get_rules(self, category: str) -> list[Any]:
        return [r for r in self.rules if getattr(r, "category", None) == category]


registry = RuleRegistry()
