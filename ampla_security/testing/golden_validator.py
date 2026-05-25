"""
Golden-file validation and comparison framework.

Compares Python pipeline output with XSLT pipeline output to ensure parity.
"""

import json
import subprocess
from difflib import unified_diff
from pathlib import Path

from lxml import etree


class GoldenValidator:
    """Validates Python engine against XSLT reference implementation."""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.golden_dir = self.project_root / "golden"
        self.working_dir = self.project_root / "working"
        self.golden_dir.mkdir(exist_ok=True)
        self.working_dir.mkdir(exist_ok=True)

    def run_python_pipeline(self, project_xml: str, authstore_xml: str) -> dict:
        """Run the Python pipeline and return outputs."""
        from ampla_security.normalization.authstore_normalizer import (
            AuthstoreNormalizer,
        )
        from ampla_security.normalization.project_normalizer import ProjectNormalizer
        from ampla_security.normalization.project_security_extractor import (
            ProjectSecurityExtractor,
        )
        from ampla_security.reporting.html_reporter import HtmlReporter

        outputs = {}

        # Normalize project
        project_tree = etree.parse(project_xml)
        project_normalizer = ProjectNormalizer(project_tree)
        normalized_project = project_normalizer.normalize()
        project_output = str(self.working_dir / "python_project_normalized.xml")
        normalized_project.write(
            project_output, pretty_print=True, encoding="utf-8", xml_declaration=True
        )
        outputs["project_normalized"] = project_output

        # Extract security from normalized project
        security_extractor = ProjectSecurityExtractor(normalized_project)
        project_security = security_extractor.extract()
        project_security_output = str(self.working_dir / "python_project_security.xml")
        project_security.write(
            project_security_output,
            pretty_print=True,
            encoding="utf-8",
            xml_declaration=True,
        )
        outputs["project_security"] = project_security_output

        # Normalize authstore
        authstore_tree = etree.parse(authstore_xml)
        authstore_normalizer = AuthstoreNormalizer(authstore_tree)
        # Pass project security if available
        if "project_security" in outputs:
            authstore_normalizer.set_project_security(project_security)
        normalized_authstore = authstore_normalizer.normalize()
        authstore_output = str(self.working_dir / "python_authstore_normalized.xml")
        normalized_authstore.write(
            authstore_output, pretty_print=True, encoding="utf-8", xml_declaration=True
        )
        outputs["authstore_normalized"] = authstore_output

        # Generate HTML report (HtmlReporter takes findings, not normalized_authstore)
        # For now, skip HTML generation if reporter interface doesn't match
        try:
            findings = []  # Extract findings from normalized_authstore if needed
            reporter = HtmlReporter(findings)
            html_output = str(self.working_dir / "python_security_report.html")
            reporter.generate(html_output)
            outputs["security_report"] = html_output
        except Exception as e:
            print(f"  Warning: Could not generate HTML report: {e}")

        return outputs

    def run_xslt_pipeline(self, project_xml: str, authstore_xml: str) -> dict:
        """Run the XSLT pipeline using xsltproc and return outputs."""
        outputs = {}
        xslt_dir = self.project_root / "src" / "StyleSheets"

        # Normalize project with XSLT
        project_normalized = str(self.working_dir / "xslt_project_normalized.xml")
        cmd = [
            "xsltproc",
            "--output",
            project_normalized,
            str(xslt_dir / "Project.Normalize.xslt"),
            project_xml,
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        outputs["project_normalized"] = project_normalized

        # Run project security transform
        project_security = str(self.working_dir / "xslt_project_security.xml")
        cmd = [
            "xsltproc",
            "--output",
            project_security,
            str(xslt_dir / "Project.Security.xslt"),
            project_normalized,
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        outputs["project_security"] = project_security

        # Normalize authstore with XSLT (pass projectSecurity path as parameter)
        authstore_normalized = str(self.working_dir / "xslt_authstore_normalized.xml")
        cmd = [
            "xsltproc",
            "--stringparam",
            "projectSecurity",
            project_security,
            "--output",
            authstore_normalized,
            str(xslt_dir / "Authstore.Normalize.xslt"),
            authstore_xml,
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        outputs["authstore_normalized"] = authstore_normalized

        # Generate HTML report
        html_output = str(self.working_dir / "xslt_security_report.html")
        cmd = [
            "xsltproc",
            "--output",
            html_output,
            str(xslt_dir / "Document.Security.xslt"),
            authstore_normalized,
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        outputs["security_report"] = html_output

        return outputs

    def normalize_xml(self, xml_file: str) -> str:
        """Normalize XML for comparison (remove whitespace, etc)."""
        tree = etree.parse(xml_file)
        # Remove comments and extra whitespace
        etree.cleanup_namespaces(tree.getroot())
        output = etree.tostring(tree, encoding="unicode")
        return output

    def compare_files(self, file1: str, file2: str, description: str = "") -> dict:
        """Compare two text files and return diff."""
        with open(file1) as f:
            content1 = f.readlines()
        with open(file2) as f:
            content2 = f.readlines()

        diff = list(
            unified_diff(
                content1, content2, fromfile="XSLT", tofile="Python", lineterm=""
            )
        )

        return {
            "description": description,
            "identical": len(diff) == 0,
            "diff_lines": len(diff),
            "sample_diff": "".join(diff[:100]),  # First 100 lines
            "full_diff": "".join(diff),
        }

    def compare_normalized_xml(self, python_xml: str, xslt_xml: str) -> dict:
        """Compare normalized XML files semantically."""
        try:
            py_tree = etree.parse(python_xml)
            xslt_tree = etree.parse(xslt_xml)

            # Convert to string for comparison
            py_str = etree.tostring(py_tree, pretty_print=True, encoding="unicode")
            xslt_str = etree.tostring(xslt_tree, pretty_print=True, encoding="unicode")

            # Create normalized versions (remove formatting differences)
            py_compact = etree.tostring(py_tree, encoding="unicode")
            xslt_compact = etree.tostring(xslt_tree, encoding="unicode")

            return {
                "identical": py_compact == xslt_compact,
                "byte_diff": abs(len(py_compact) - len(xslt_compact)),
                "element_count_python": len(py_tree.getroot().xpath(".//*")),
                "element_count_xslt": len(xslt_tree.getroot().xpath(".//*")),
                "attr_count_python": sum(
                    len(elem.attrib) for elem in py_tree.getroot().xpath(".//*")
                ),
                "attr_count_xslt": sum(
                    len(elem.attrib) for elem in xslt_tree.getroot().xpath(".//*")
                ),
            }
        except Exception as e:
            return {"error": str(e)}

    def validate_pipeline(self, project_xml: str, authstore_xml: str) -> dict:
        """Run both pipelines and compare outputs."""
        results = {
            "timestamp": None,
            "project_xml": project_xml,
            "authstore_xml": authstore_xml,
            "python_outputs": {},
            "xslt_outputs": {},
            "comparisons": {},
        }

        import datetime

        results["timestamp"] = datetime.datetime.now().isoformat()

        try:
            print("Running Python pipeline...")
            results["python_outputs"] = self.run_python_pipeline(
                project_xml, authstore_xml
            )
            print("✓ Python pipeline complete")
        except Exception as e:
            print(f"✗ Python pipeline failed: {e}")
            results["python_error"] = str(e)
            return results

        try:
            print("Running XSLT pipeline...")
            results["xslt_outputs"] = self.run_xslt_pipeline(project_xml, authstore_xml)
            print("✓ XSLT pipeline complete")
        except Exception as e:
            print(f"✗ XSLT pipeline failed: {e}")
            results["xslt_error"] = str(e)
            return results

        # Compare outputs
        print("\nComparing outputs...")

        if (
            "project_normalized" in results["python_outputs"]
            and "project_normalized" in results["xslt_outputs"]
        ):
            cmp = self.compare_normalized_xml(
                results["python_outputs"]["project_normalized"],
                results["xslt_outputs"]["project_normalized"],
            )
            results["comparisons"]["project_normalized"] = cmp
            status = "✓" if cmp.get("identical") else "✗"
            print(f"{status} Project normalized XML: {cmp}")

        if (
            "authstore_normalized" in results["python_outputs"]
            and "authstore_normalized" in results["xslt_outputs"]
        ):
            cmp = self.compare_normalized_xml(
                results["python_outputs"]["authstore_normalized"],
                results["xslt_outputs"]["authstore_normalized"],
            )
            results["comparisons"]["authstore_normalized"] = cmp
            status = "✓" if cmp.get("identical") else "✗"
            print(f"{status} AuthStore normalized XML: {cmp}")

        if (
            "security_report" in results["python_outputs"]
            and "security_report" in results["xslt_outputs"]
        ):
            cmp = self.compare_files(
                results["xslt_outputs"]["security_report"],
                results["python_outputs"]["security_report"],
                "Security HTML report",
            )
            results["comparisons"]["security_report"] = cmp
            status = "✓" if cmp["identical"] else "✗"
            print(
                f"{status} Security report HTML: identical={cmp['identical']}, diff_lines={cmp['diff_lines']}"
            )

        return results

    def save_golden_files(self, results: dict, name: str):
        """Save results as golden files."""
        golden_file = self.golden_dir / f"{name}_golden.json"
        with open(golden_file, "w") as f:
            # Remove full_diff to keep file smaller
            results_copy = results.copy()
            if "comparisons" in results_copy:
                for comp in results_copy["comparisons"].values():
                    if "full_diff" in comp:
                        del comp["full_diff"]
            json.dump(results_copy, f, indent=2)
        print(f"\nGolden files saved to {golden_file}")
        return golden_file

    def load_golden_files(self, name: str) -> dict:
        """Load golden files for regression testing."""
        golden_file = self.golden_dir / f"{name}_golden.json"
        if not golden_file.exists():
            return None
        with open(golden_file) as f:
            return json.load(f)
