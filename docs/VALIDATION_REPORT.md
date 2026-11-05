# Validation Status

This report records the repository validation status after B01–B17 were
implemented.

## Automated tests

The complete pytest suite passes: **76 tests passed**. The suite contains
**17 test modules** covering:

- project normalization and specialized transforms;
- project security extraction;
- AuthStore schema, scopes, role links, and user resolution;
- HTML and text reports;
- CLI end-to-end behavior; and
- the XML golden/parity validator.

The test command is:

```sh
python -m pytest -q
```

The latest recorded coverage is **83% statement coverage** across
`ampla_security`. This is a code-coverage measure; it is not a weighted
migration-parity score.

## Parity checks

The executable validator compares Python and XSLT outputs for:

1. normalized project XML;
2. extracted project security XML; and
3. normalized AuthStore/Security XML.

The HTML and both text reports have separate live-XSLT and golden-output
comparisons in pytest. The validation strategy documents canonicalization and
the limits of parity claims.

## Interpretation

Generated `hash` values intentionally differ because Python uses SHA1 while
the XSLT uses `generate-id()`. Tests compare hash attribute presence and
location. Serializer formatting is canonicalized narrowly. No weighted
behavior-coverage calculation has been performed, so the 90% migration
completeness estimate remains qualitative and does not establish a >90% parity
claim.
