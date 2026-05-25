from pathlib import Path
from typing import Any


class HtmlReporter:
    """
    Generates HTML security reports using package templates.
    """

    def __init__(self, findings: list[dict[str, Any]] | list[Any]):
        self.findings = findings
        self.template_dir = Path(__file__).resolve().parent / "templates"

    def generate(self, output_path: str | Path) -> None:
        base_template = self._load_template("base.html")
        report_template = self._load_template("security_report.html")
        report_content = self._render_report_template(report_template)
        html = base_template.replace("{{ content }}", report_content)

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

    def _load_template(self, filename: str) -> str:
        path = self.template_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Missing template: {filename}")
        return path.read_text(encoding="utf-8")

    def _render_report_template(self, template: str) -> str:
        lines: list[str] = []
        in_loop = False

        for line in template.splitlines():
            stripped = line.strip()

            if stripped.startswith("{% for finding in findings %}"):
                in_loop = True
                continue

            if stripped.startswith("{% endfor %}"):
                in_loop = False
                continue

            if in_loop:
                if "{{ finding.severity }}" in line or "{{ finding.message }}" in line:
                    for finding in self.findings:
                        item_html = line

                        severity = (
                            finding.get("severity")
                            if isinstance(finding, dict)
                            else getattr(finding, "severity", "")
                        )
                        message = (
                            finding.get("message")
                            if isinstance(finding, dict)
                            else getattr(finding, "message", "")
                        )

                        item_html = item_html.replace(
                            "{{ finding.severity }}",
                            self._escape(self._to_text(severity)),
                        )
                        item_html = item_html.replace(
                            "{{ finding.message }}",
                            self._escape(self._to_text(message)),
                        )

                        lines.append(item_html)
                    continue

            lines.append(line)

        return "\n".join(lines)

    def _escape(self, value: str) -> str:
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    def _to_text(self, value: Any) -> str:
        return "" if value is None else str(value)
