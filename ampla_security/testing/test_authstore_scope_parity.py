from pathlib import Path

from lxml import etree

from ampla_security.normalization.authstore_normalizer import AuthstoreNormalizer

AUTHSTORE_XML = """\
<AzAdminManager>
  <AzApplication Name="ScopeParity">
    <AzScope Name="matched" Description="Security scope for Matched Scope"/>
    <AzScope Name="auth-only" Description="Security scope for Missing Project"/>
  </AzApplication>
</AzAdminManager>
"""

PROJECT_SECURITY_XML = """\
<Security>
  <Users/>
  <Scopes>
    <Scope name="{Global}" scopeId="00000000-0000-0000-0000-000000000000"
           fullName="{Global}"/>
    <Scope id="matched" scopeId="matched" name="Matched Scope"
           fullName="Project.Area.Matched Scope"/>
    <Scope id="project-only" scopeId="project-only" name="Project Only"
           fullName="Project.Area.Project Only"/>
    <Scope scopeId="no-item-id" name="Not an item scope"
           fullName="Project.Not an item scope"/>
  </Scopes>
</Security>
"""

STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Authstore.Normalize.xslt"
)


def _canonical_xml(node: etree._Element) -> bytes:
    for element in node.iter():
        if element.text is not None and not element.text.strip():
            element.text = None
        if element.tail is not None and not element.tail.strip():
            element.tail = None
    return etree.tostring(node, method="c14n")


def test_scope_reconciliation_matches_xslt(tmp_path):
    authstore_tree = etree.ElementTree(etree.fromstring(AUTHSTORE_XML.encode()))
    project_security_tree = etree.ElementTree(
        etree.fromstring(PROJECT_SECURITY_XML.encode())
    )
    normalizer = AuthstoreNormalizer(authstore_tree)
    normalizer.set_project_security(project_security_tree)
    python_output = normalizer.normalize()

    project_security_path = tmp_path / "project_security.xml"
    project_security_tree.write(str(project_security_path), encoding="utf-8")
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    xslt_output = transform(
        authstore_tree,
        projectSecurity=etree.XSLT.strparam(str(project_security_path)),
    )

    python_scopes = python_output.find("Scopes")
    xslt_scopes = xslt_output.find("Scopes")
    assert python_scopes is not None
    assert xslt_scopes is not None
    assert _canonical_xml(python_scopes) == _canonical_xml(xslt_scopes)
    assert [
        (
            scope.get("name"),
            scope.get("scopeId"),
            scope.get("valid"),
            scope.get("invalid"),
        )
        for scope in python_scopes
    ] == [
        (
            "{Global}",
            "00000000-0000-0000-0000-000000000000",
            "Default scope",
            None,
        ),
        ("Matched Scope", "matched", "Scope is Valid", None),
        (
            "Missing Project",
            "auth-only",
            None,
            "Warning: Scope does not exist in Ampla Project.",
        ),
        (
            "Project.Area.Project Only",
            "project-only",
            None,
            "Warning: Scope does not exist in Authorization Store (AuthStore.xml)",
        ),
    ]


def test_project_only_global_scope_is_not_duplicated():
    authstore_tree = etree.ElementTree(
        etree.fromstring(
            b"<AzAdminManager><AzApplication Name='Empty'/></AzAdminManager>"
        )
    )
    project_security_tree = etree.ElementTree(
        etree.fromstring(
            b'<Security><Users/><Scopes><Scope name="{Global}" '
            b'scopeId="00000000-0000-0000-0000-000000000000"/>'
            b'<Scope id="project" scopeId="project" name="Project Scope" '
            b'fullName="Project.Project Scope"/></Scopes></Security>'
        )
    )
    normalizer = AuthstoreNormalizer(authstore_tree)
    normalizer.set_project_security(project_security_tree)

    scopes = normalizer.normalize().xpath("./Scopes/Scope")
    assert [scope.get("scopeId") for scope in scopes] == [
        "00000000-0000-0000-0000-000000000000",
        "project",
    ]
