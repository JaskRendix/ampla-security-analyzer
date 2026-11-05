# Security Analysis

The Python application generates its security report from a normalized
`Security` document. It does not treat arbitrary XML matches as security
findings.

## Pipeline inputs

- Project XML supplies project items, users, scopes, identities, and security
  properties.
- AuthStore XML supplies operations, roles, tasks, scopes, and role members.

Project security extraction provides the user and scope data used during
AuthStore normalization. Member resolution checks project Identity matches,
SecurityID matches, well-known SIDs, and then the unresolved-user fallback.
Project and AuthStore scopes are reconciled and marked according to the
normalization rules.

## HTML report

The report is based on `Document.Security.xslt` and includes:

- roles by operation;
- valid and invalid scopes;
- user authentication and identity details;
- allowed, denied, and invalid assignments; and
- scope listings.

The report escapes text values and includes the legacy report structure,
stylesheet reference, and navigation anchors. The roles and assignments text
reports are generated separately from the same normalized `Security`
document.

## Implementation references

- `ampla_security/normalization/project_security_extractor.py` extracts
  project users and scopes.
- `ampla_security/normalization/authstore_normalizer.py` builds the normalized
  `Security` document and resolves members.
- `ampla_security/reporting/html_reporter.py` renders the HTML report.
- `ampla_security/reporting/security_text_reporter.py` renders both text
  reports.
- `src/StyleSheets/` contains the reference XSLT stylesheets.

Report behavior is tested against live XSLT output and checked-in fixtures in
`ampla_security/testing/fixtures/security_report/`.
