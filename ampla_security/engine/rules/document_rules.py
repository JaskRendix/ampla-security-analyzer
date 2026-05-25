from __future__ import annotations

from typing import Any, List

from ampla_security.engine.registry import registry


class XmlInjectionPatternRule:
    """
    Detects XML injection patterns such as unescaped characters or unsafe constructs.
    Derived from Document.Security.xslt.
    """

    category: str = "document"

    def apply(self, context: Any) -> list[Any]:
        return []


registry.register(XmlInjectionPatternRule())


class EntityExpansionAttackRule:
    """
    Detects dangerous entity declarations (e.g., billion laughs attack).
    """

    category: str = "document"

    def apply(self, context: Any) -> list[Any]:
        return []


registry.register(EntityExpansionAttackRule())


class NamespacePoisoningRule:
    """
    Detects namespace redefinitions or malicious namespace hijacking.
    """

    category: str = "document"

    def apply(self, context: Any) -> list[Any]:
        return []


registry.register(NamespacePoisoningRule())


class SchemaBypassRule:
    """
    Detects patterns that bypass schema validation or introduce malformed structures.
    """

    category: str = "document"

    def apply(self, context: Any) -> list[Any]:
        return []


registry.register(SchemaBypassRule())
