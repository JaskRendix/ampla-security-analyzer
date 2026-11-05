# Developer Guide

## Repository layout

```text
ampla_security/
├── cli/                 # Command-line pipeline
├── normalization/       # Project, security, and AuthStore transforms
├── reporting/           # HTML and text reports
├── testing/             # pytest modules, fixtures, and parity validator
├── utils/               # Shared helpers
└── xml/                 # XML loading and utilities
src/StyleSheets/         # Original XSLT references
docs/                    # Current documentation and migration history
```

The CLI pipeline is implemented in
`ampla_security/cli/analyze.py`. It invokes the normalizers and reporters
directly. The separate `engine/` package is not part of this CLI pipeline.

## Setup and tests

The project requires Python 3.10 or later and `lxml`. Install development
dependencies in a virtual environment:

```sh
python3 -m pip install -e ".[dev]"
```

On systems where the interpreter is named `python`, substitute `python`.
Run the complete suite:

```sh
python3 -m pytest -q
```

Tests live in `ampla_security/testing/`. Parity tests use the original XSLT
files and checked-in input/output fixtures. Review
[Parity Validation](PARITY_VALIDATION_STRATEGY.md) before changing canonical
comparison rules or goldens.

## Pipeline

```sh
python3 -m ampla_security.cli.analyze \
  --project project.xml \
  --authstore authstore.xml \
  --output-dir Output
```

The CLI writes three XML intermediates and the HTML, roles, and assignments
reports. The optional language-document parameter is currently available
through the `ProjectNormalizer` API; the CLI does not expose a language
document option.

## Changing behavior

When modifying a normalizer or reporter:

1. Locate the corresponding XSLT template and existing Python method in
   [Normalization Mapping](NORMALIZATION_MAPPING.md).
2. Add or update a focused fixture and test that asserts the expected output.
3. Compare output with the reference XSLT when the corresponding transform is
   available.
4. Run the focused test and the full suite.
5. Update the relevant user or parity documentation if observable behavior or
   an accepted comparison difference changes.

Do not broaden canonicalization to hide a structural or semantic difference.
Do not regenerate expected files without reviewing the XSLT output.

## Documentation

- [Security Pipeline](SECURITY_PIPELINE.md) describes the CLI stages and
  artifacts.
- [Security Analysis](SECURITY_ANALYSIS.md) describes report content.
- [Parity Validation](PARITY_VALIDATION_STRATEGY.md) defines tests and
  comparison rules.
