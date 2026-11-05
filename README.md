# Ampla Security Analysis

A Python implementation of the Ampla Security Analysis pipeline. It replaces
the original XSLT orchestration with a Python command-line pipeline while
retaining the XSLT stylesheets as behavioral references and parity-test
fixtures.

The migration is complete for the behaviors recorded in the migration history.
The project is in maintenance mode. The estimated migration completeness is
90%; this is a qualitative assessment, not a weighted parity measurement.

## What the system does

The pipeline accepts a project XML file and an AuthStore XML file. It:

1. Normalizes project XML.
2. Extracts project security users and scopes.
3. Normalizes AuthStore data and reconciles it with project security.
4. Generates the Security HTML report.
5. Generates the roles and assignments text reports.

Project normalization includes item paths and hashes, selective property
handling, class definitions, translations, expressions, DecisionMatrix items,
Favorites, SOAP payloads, EquipmentTypes, and subscriptions. AuthStore
normalization includes operations, role links, scopes, member resolution, and
well-known SID handling.

## Requirements and installation

- Python 3.10 or later
- `lxml`

Install the package and development dependencies:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
```

On Windows, use `py -3` in place of `python3` and activate the environment
with `.venv\Scripts\activate`.

## Command-line interface

Run the complete pipeline:

```sh
python3 -m ampla_security.cli.analyze \
  --project AmplaProject.xml \
  --authstore AuthStore.xml \
  --output-dir Output
```

`--project` and `--authstore` are required. `--output-dir` is optional and
defaults to `Output`. Use `--help` to display the command options. Invalid or
unreadable inputs return a non-zero exit status and an error message.

The output directory contains:

| File | Description |
|---|---|
| `project.xml` | Normalized project |
| `project.security.xml` | Extracted project security data |
| `authstore.xml` | Normalized Security document |
| `Project.Security.html` | Security report |
| `Project.Security.Roles.txt` | Roles report |
| `Project.Security.Assignments.txt` | Assignments report |

Transformations finish before the output artifacts are written.

## Python API

```python
from lxml import etree
from ampla_security.normalization.project_normalizer import ProjectNormalizer

project = etree.parse("AmplaProject.xml")
normalized = ProjectNormalizer(project).normalize()
```

An optional language document can be passed as `language_document`. It accepts
a path, an `lxml` element tree, or a root element. Translation entries use the
original `html/body/div[@id]` format, where the `id` matches an item or class
name.

## Validation and tests

Run the full test suite, including coverage:

```sh
python3 -m pytest -q
```

The suite includes focused normalization tests, XSLT parity comparisons,
golden-file checks, reporting tests, and CLI integration tests. Current
coverage is 83% statement coverage; this is not a migration-parity percentage.

Run the XML parity validator against the committed synthetic corpus:

```sh
python3 -m ampla_security.testing.golden_validator \
  --project ampla_security/testing/fixtures/parity/project.xml \
  --authstore ampla_security/testing/fixtures/parity/authstore.xml \
  --project-root . \
  --working-dir working/parity
```

The validator compares project normalization, project security extraction,
and AuthStore normalization with the checked-in XSLT pipeline. Dedicated tests
compare the HTML and text reports with XSLT output and checked-in goldens.
See [Parity Validation](docs/PARITY_VALIDATION_STRATEGY.md) for comparison
rules and supported claim boundaries.

## Repository guide

- `ampla_security/normalization/` — project, security extraction, and
  AuthStore normalization
- `ampla_security/reporting/` — HTML and text reports
- `ampla_security/cli/` — pipeline command
- `ampla_security/testing/` — pytest suite, parity harness, fixtures, and
  golden outputs
- `src/StyleSheets/` — original XSLT behavioral references
- `docs/` — current usage, pipeline, and validation documentation

## License and provenance

This project migrates the workflow of the MIT-licensed
[Ampla Security Analysis project](https://github.com/Ampla/SecurityAnalysis).
The Python implementation preserves behavioral compatibility with the original
XSLT pipeline as its migration goal. The original stylesheets remain in this
repository as references for tests and output comparisons. Copyright and
license information is in [LICENSE](LICENSE); the license text is unchanged.
The current file ends with a literal ellipsis and needs review before
redistribution.
