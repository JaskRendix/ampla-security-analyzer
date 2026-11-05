"""Compare the Python normalization pipeline with the checked-in XSLT pipeline."""

import argparse
import copy
import json
import re
import sys
from difflib import unified_diff
from io import BytesIO
from pathlib import Path
from typing import Any

from lxml import etree

PIPELINE_STAGES = (
    "project_normalized",
    "project_security",
    "authstore_normalized",
)

CANONICALIZATION_POLICY = {
    "generated_hashes": (
        "Compare @hash presence and location on normalized Item nodes, extracted "
        "User/Scope nodes, and normalized Security User nodes, but ignore values "
        "because Python SHA-1 hashes and XSLT generate-id() values are generated "
        "by different mechanisms."
    ),
    "translation_count_comment": (
        "Ignore only the top-level XSLT comment matching '<integer> Translations' "
        "in project_normalized. It is stylesheet diagnostic metadata; all other "
        "comments and XML content remain part of the comparison."
    ),
    "formatting_whitespace": (
        "Ignore whitespace-only indentation only in known element-only containers "
        "and around the nested Identity element inside Property[@name='Identity']. "
        "Preserve all other text, including whitespace in property and identity values."
    ),
    "other_differences": (
        "Attribute order is canonicalized. Element order, names, attributes, "
        "significant text, and comments are compared."
    ),
}

_TRANSLATION_COMMENT = re.compile(r"^\d+ Translations$")
_GENERATED_HASH_PATHS = {
    "project_normalized": {"Item"},
    "project_security": {"User", "Scope"},
    "authstore_normalized": {"User"},
}
_ELEMENT_ONLY_CONTAINERS = {
    "Favorites",
    "Input",
    "InputRule",
    "Item",
    "ItemLinkCollection",
    "Links",
    "Operation",
    "Operations",
    "Project",
    "Properties",
    "Role",
    "RoleDefinition",
    "RoleDefinitions",
    "RoleLink",
    "Scope",
    "Scopes",
    "Security",
    "Users",
    "User",
}


class ParityValidationError(RuntimeError):
    """Raised when a pipeline stage is missing or differs from its reference."""

    def __init__(self, message: str, results: dict[str, Any] | None = None):
        super().__init__(message)
        self.results = results


class GoldenValidator:
    """Run and compare all supported Python and XSLT normalization stages."""

    def __init__(self, project_root: str | Path | None = None):
        self.project_root = (
            Path(project_root).resolve()
            if project_root is not None
            else Path(__file__).resolve().parents[2]
        )
        self.golden_dir = self.project_root / "golden"
        self.working_dir = self.project_root / "working"
        self.stylesheet_dir = self.project_root / "src" / "StyleSheets"

    def run_python_pipeline(
        self, project_xml: str | Path, authstore_xml: str | Path
    ) -> dict[str, str]:
        """Run project normalization, security extraction, and AuthStore normalization."""
        from ampla_security.normalization.authstore_normalizer import (
            AuthstoreNormalizer,
        )
        from ampla_security.normalization.project_normalizer import ProjectNormalizer
        from ampla_security.normalization.project_security_extractor import (
            ProjectSecurityExtractor,
        )

        self.working_dir.mkdir(parents=True, exist_ok=True)
        project_tree = self._parse_input(project_xml, "project")
        normalized_project = ProjectNormalizer(project_tree).normalize()
        project_output = self.working_dir / "python_project_normalized.xml"
        self._write_tree(normalized_project, project_output)

        normalized_project = self._parse_input(project_output, "normalized project")
        project_security = ProjectSecurityExtractor(normalized_project).extract()
        security_output = self.working_dir / "python_project_security.xml"
        self._write_tree(project_security, security_output)

        authstore_tree = self._parse_input(authstore_xml, "AuthStore")
        authstore_normalizer = AuthstoreNormalizer(authstore_tree)
        authstore_normalizer.set_project_security(project_security)
        normalized_authstore = authstore_normalizer.normalize()
        authstore_output = self.working_dir / "python_authstore_normalized.xml"
        self._write_tree(normalized_authstore, authstore_output)

        return {
            "project_normalized": str(project_output),
            "project_security": str(security_output),
            "authstore_normalized": str(authstore_output),
        }

    def run_xslt_pipeline(
        self, project_xml: str | Path, authstore_xml: str | Path
    ) -> dict[str, str]:
        """Run the three reference stylesheets using the project's lxml dependency."""
        self.working_dir.mkdir(parents=True, exist_ok=True)
        project_tree = self._parse_input(project_xml, "project")
        authstore_tree = self._parse_input(authstore_xml, "AuthStore")

        project_result = self._transform("Project.Normalize.xslt", project_tree)
        project_output = self.working_dir / "xslt_project_normalized.xml"
        self._write_result(project_result, project_output)

        normalized_project = self._parse_input(
            project_output, "XSLT normalized project"
        )
        security_result = self._transform("Project.Security.xslt", normalized_project)
        security_output = self.working_dir / "xslt_project_security.xml"
        self._write_result(security_result, security_output)

        authstore_result = self._transform(
            "Authstore.Normalize.xslt",
            authstore_tree,
            projectSecurity=etree.XSLT.strparam(str(security_output.resolve())),
        )
        authstore_output = self.working_dir / "xslt_authstore_normalized.xml"
        self._write_result(authstore_result, authstore_output)

        return {
            "project_normalized": str(project_output),
            "project_security": str(security_output),
            "authstore_normalized": str(authstore_output),
        }

    def validate_pipeline(
        self, project_xml: str | Path, authstore_xml: str | Path
    ) -> dict[str, Any]:
        """Run both pipelines and fail if a stage is missing or differs."""
        python_outputs = self.run_python_pipeline(project_xml, authstore_xml)
        xslt_outputs = self.run_xslt_pipeline(project_xml, authstore_xml)

        self._validate_output_set("Python", python_outputs)
        self._validate_output_set("XSLT", xslt_outputs)

        comparisons: dict[str, dict[str, Any]] = {}
        for stage in PIPELINE_STAGES:
            python_path = Path(python_outputs[stage])
            xslt_path = Path(xslt_outputs[stage])
            for label, output_path in (
                ("Python", python_path),
                ("XSLT", xslt_path),
            ):
                if not output_path.is_file():
                    raise ParityValidationError(
                        f"{label} pipeline did not produce required stage "
                        f"'{stage}': {output_path}"
                    )

            comparisons[stage] = self.compare_normalized_xml(
                python_path, xslt_path, stage=stage
            )

        results = {
            "passed": all(result["identical"] for result in comparisons.values()),
            "project_xml": str(Path(project_xml).resolve()),
            "authstore_xml": str(Path(authstore_xml).resolve()),
            "python_outputs": python_outputs,
            "xslt_outputs": xslt_outputs,
            "comparisons": comparisons,
            "canonicalization": CANONICALIZATION_POLICY.copy(),
            "xslt_runtime": {
                "processor": "lxml/libxslt",
                "lxml": list(etree.LXML_VERSION),
                "libxml": list(etree.LIBXML_VERSION),
                "libxslt": list(etree.LIBXSLT_VERSION),
            },
        }

        failures = [
            f"{stage}: {comparison['summary']}"
            for stage, comparison in comparisons.items()
            if not comparison["identical"]
        ]
        if failures:
            diffs = [
                f"\n[{stage}]\n{comparison['diff']}"
                for stage, comparison in comparisons.items()
                if not comparison["identical"]
            ]
            raise ParityValidationError(
                "Python/XSLT parity failed: "
                + "; ".join(failures)
                + "\n"
                + "\n".join(diffs),
                results,
            )
        return results

    def normalize_xml(
        self, xml_file: str | Path, stage: str = "project_normalized"
    ) -> str:
        """Return the stage-aware canonical XML representation."""
        tree = self._parse_input(xml_file, stage)
        return self._canonical_xml(tree, stage).decode("utf-8")

    def compare_normalized_xml(
        self,
        python_xml: str | Path,
        xslt_xml: str | Path,
        stage: str = "project_normalized",
    ) -> dict[str, Any]:
        """Compare XML content while applying only the documented stage rules."""
        python_tree = self._parse_input(python_xml, f"Python {stage}")
        xslt_tree = self._parse_input(xslt_xml, f"XSLT {stage}")
        hash_presence_matches = self._generated_hash_paths(
            python_tree, stage
        ) == self._generated_hash_paths(xslt_tree, stage)
        python_xml_canonical = self._canonical_xml(
            python_tree, stage, ignore_generated_hashes=hash_presence_matches
        )
        xslt_xml_canonical = self._canonical_xml(
            xslt_tree, stage, ignore_generated_hashes=hash_presence_matches
        )
        python_text = self._pretty_xml(python_xml_canonical)
        xslt_text = self._pretty_xml(xslt_xml_canonical)
        diff = "".join(
            unified_diff(
                xslt_text.splitlines(keepends=True),
                python_text.splitlines(keepends=True),
                fromfile=f"XSLT {stage}",
                tofile=f"Python {stage}",
            )
        )
        identical = python_xml_canonical == xslt_xml_canonical
        identical = identical and hash_presence_matches
        return {
            "stage": stage,
            "identical": identical,
            "summary": (
                "canonical XML matches"
                if identical
                else (
                    "generated hash attributes are missing or extra"
                    if not hash_presence_matches
                    else "canonical XML differs"
                )
            ),
            "generated_hash_presence_matches": hash_presence_matches,
            "diff": diff,
        }

    def save_golden_files(self, results: dict[str, Any], name: str) -> Path:
        """Save a deterministic JSON report for a completed validation run."""
        self.golden_dir.mkdir(parents=True, exist_ok=True)
        golden_file = self.golden_dir / f"{name}_golden.json"
        with golden_file.open("w", encoding="utf-8") as output:
            json.dump(results, output, indent=2, sort_keys=True)
            output.write("\n")
        return golden_file

    def load_golden_files(self, name: str) -> dict[str, Any]:
        """Load a saved JSON validation report or fail if it does not exist."""
        golden_file = self.golden_dir / f"{name}_golden.json"
        with golden_file.open(encoding="utf-8") as source:
            return json.load(source)

    def _transform(
        self, stylesheet_name: str, source: etree._ElementTree, **parameters: Any
    ) -> etree._XSLTResultTree:
        stylesheet_path = self.stylesheet_dir / stylesheet_name
        if not stylesheet_path.is_file():
            raise FileNotFoundError(
                f"Required XSLT stylesheet not found: {stylesheet_path}"
            )
        transform = etree.XSLT(etree.parse(str(stylesheet_path)))
        return transform(source, **parameters)

    @staticmethod
    def _parse_input(path: str | Path, label: str) -> etree._ElementTree:
        input_path = Path(path)
        if not input_path.is_file():
            raise FileNotFoundError(f"Required {label} XML not found: {input_path}")
        return etree.parse(str(input_path))

    @staticmethod
    def _write_tree(tree: etree._ElementTree, output_path: Path) -> None:
        tree.write(
            str(output_path),
            encoding="utf-8",
            xml_declaration=True,
            pretty_print=False,
        )

    @staticmethod
    def _write_result(result: etree._XSLTResultTree, output_path: Path) -> None:
        output_path.write_bytes(
            etree.tostring(result, encoding="UTF-8", xml_declaration=True)
        )

    @staticmethod
    def _canonical_xml(
        tree: etree._ElementTree,
        stage: str,
        ignore_generated_hashes: bool = True,
    ) -> bytes:
        root = tree.getroot()
        if root is None:
            raise ValueError(f"{stage} output has no document element")
        canonical_root = copy.deepcopy(root)
        canonical_tree = etree.ElementTree(canonical_root)
        preceding = []
        sibling = root.getprevious()
        while sibling is not None:
            preceding.append(sibling)
            sibling = sibling.getprevious()
        for sibling in reversed(preceding):
            if stage == "project_normalized" and (
                isinstance(sibling, etree._Comment)
                and _TRANSLATION_COMMENT.fullmatch(sibling.text or "")
            ):
                continue
            canonical_root.addprevious(copy.deepcopy(sibling))

        following = []
        sibling = root.getnext()
        while sibling is not None:
            following.append(sibling)
            sibling = sibling.getnext()
        for sibling in reversed(following):
            canonical_root.addnext(copy.deepcopy(sibling))

        generated_hash_tags = _GENERATED_HASH_PATHS.get(stage, set())
        for element in canonical_tree.getroot().iter():
            if (
                ignore_generated_hashes
                and element.tag in generated_hash_tags
                and "hash" in element.attrib
            ):
                del element.attrib["hash"]
            if (
                element.tag in _ELEMENT_ONLY_CONTAINERS
                and len(element)
                and element.text is not None
                and not element.text.strip()
            ):
                element.text = None
            if (
                element.tag == "Property"
                and element.get("name") == "Identity"
                and element.find("Identity") is not None
                and element.text is not None
                and not element.text.strip()
            ):
                element.text = None
            if (
                element.getparent() is not None
                and (
                    element.getparent().tag in _ELEMENT_ONLY_CONTAINERS
                    or (
                        element.getparent().tag == "Property"
                        and element.getparent().get("name") == "Identity"
                        and element.getparent().find("Identity") is not None
                    )
                )
                and element.tail is not None
                and not element.tail.strip()
            ):
                element.tail = None

        return etree.tostring(
            canonical_tree,
            method="c14n",
            with_comments=True,
        )

    @staticmethod
    def _generated_hash_paths(tree: etree._ElementTree, stage: str) -> set[str]:
        generated_hash_tags = _GENERATED_HASH_PATHS.get(stage, set())
        return {
            tree.getpath(element)
            for element in tree.getroot().iter()
            if element.tag in generated_hash_tags and "hash" in element.attrib
        }

    @staticmethod
    def _pretty_xml(canonical_xml: bytes) -> str:
        tree = etree.parse(BytesIO(canonical_xml))
        return etree.tostring(tree, encoding="unicode", pretty_print=True)

    @staticmethod
    def _validate_output_set(label: str, outputs: dict[str, str]) -> None:
        actual = set(outputs)
        expected = set(PIPELINE_STAGES)
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing or extra:
            details = []
            if missing:
                details.append(f"missing stages: {', '.join(missing)}")
            if extra:
                details.append(f"unexpected stages: {', '.join(extra)}")
            raise ParityValidationError(
                f"{label} pipeline output set is invalid ({'; '.join(details)})"
            )


def main(argv: list[str] | None = None) -> int:
    """Run parity validation from the command line."""
    parser = argparse.ArgumentParser(
        description="Compare Python normalization with the checked-in XSLT pipeline."
    )
    parser.add_argument("--project", required=True, help="Project XML input")
    parser.add_argument("--authstore", required=True, help="AuthStore XML input")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Repository root containing src/StyleSheets (default: detected root)",
    )
    parser.add_argument(
        "--working-dir",
        type=Path,
        help="Directory for generated intermediate XML files (default: <root>/working)",
    )
    args = parser.parse_args(argv)

    try:
        validator = GoldenValidator(args.project_root)
        if args.working_dir is not None:
            validator.working_dir = args.working_dir
        results = validator.validate_pipeline(args.project, args.authstore)
    except Exception as error:
        print(f"Parity validation failed: {error}", file=sys.stderr)
        return 1

    for stage in PIPELINE_STAGES:
        print(f"PASS {stage}: {results['comparisons'][stage]['summary']}")
    print("Python and XSLT outputs match for all required stages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
