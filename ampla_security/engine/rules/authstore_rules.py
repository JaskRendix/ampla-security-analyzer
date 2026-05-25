from __future__ import annotations

from typing import Any

from ampla_security.engine.registry import registry


class ExampleAuthstoreRule:
    category: str = "authstore"
    priority: int = 1
    match: str = "//AzScope"

    def apply(self, context: Any) -> list[dict[str, Any]]:
        return [
            {
                "severity": "Info",
                "message": "Sample authstore rule executed",
                "category": "authstore",
            }
        ]


registry.register(ExampleAuthstoreRule())
