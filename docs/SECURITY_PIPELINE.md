# Security Pipeline Guide

## Processing stages

The CLI runs these stages in order:

1. Parse project and AuthStore XML.
2. Normalize project items, properties, classes, expressions, and defaults.
3. Extract project users, identities, and scopes.
4. Normalize AuthStore operations, roles, members, and scopes using extracted
   project security data.
5. Render the Security HTML report.
6. Render the roles and assignments text reports.
7. Write three XML intermediates and three reports to the selected output
   directory.

## Run the pipeline

```sh
python -m ampla_security.cli.analyze \
  --project project.xml \
  --authstore authstore.xml \
  --output-dir Output
```

Both input options are required. The output directory defaults to `Output`.
The command returns a non-zero status when inputs cannot be read or parsed.
Use `--help` for the supported options.

Add `--analyze-findings` to run the optional configuration exposure scan on
the original project XML. It writes `findings.json` in the output directory.
The scan does not change the six legacy artifacts. Its findings are
heuristic, and detected property values are excluded from the JSON.

Output artifact names:

- `project.xml`
- `project.security.xml`
- `authstore.xml`
- `Project.Security.html`
- `Project.Security.Roles.txt`
- `Project.Security.Assignments.txt`
- `findings.json` (optional; only with `--analyze-findings`)

## Reports

The HTML report contains the roles-by-operation matrix, valid and invalid
scope tables, user details, and allowed, denied, and invalid assignments. The
text reports provide the legacy roles and assignments views. Both report
formats are generated from the normalized `Security` XML.

See [Security Analysis](SECURITY_ANALYSIS.md) for report content and
[Parity Validation](PARITY_VALIDATION_STRATEGY.md) for output comparison
rules.

## Test and parity commands

Run all tests and coverage:

```sh
python -m pytest -q
```

Run the XML parity validator:

```sh
python -m ampla_security.testing.golden_validator \
  --project ampla_security/testing/fixtures/parity/project.xml \
  --authstore ampla_security/testing/fixtures/parity/authstore.xml \
  --project-root . \
  --working-dir working/parity
```

The validator compares the three XML normalization stages. Dedicated pytest
modules compare the HTML and text reports against the original XSLT stylesheets
and checked-in goldens.
