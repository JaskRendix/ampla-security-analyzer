from pathlib import Path

from lxml import etree

from ampla_security.normalization.authstore_normalizer import AuthstoreNormalizer
from ampla_security.testing.golden_validator import GoldenValidator

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "authstore_user_resolution"
STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Authstore.Normalize.xslt"
)


def _python_output() -> etree._ElementTree:
    authstore_tree = etree.parse(str(FIXTURE_DIR / "authstore.xml"))
    project_security = etree.parse(str(FIXTURE_DIR / "project_security.xml"))
    normalizer = AuthstoreNormalizer(authstore_tree)
    normalizer.set_project_security(project_security)
    return normalizer.normalize()


def _xslt_output(tmp_path: Path) -> etree._ElementTree:
    authstore_tree = etree.parse(str(FIXTURE_DIR / "authstore.xml"))
    project_security_path = FIXTURE_DIR / "project_security.xml"
    result = etree.XSLT(etree.parse(str(STYLESHEET)))(
        authstore_tree,
        projectSecurity=etree.XSLT.strparam(str(project_security_path.resolve())),
    )
    output_path = tmp_path / "authstore_normalized.xml"
    output_path.write_bytes(etree.tostring(result, encoding="UTF-8"))
    return etree.parse(str(output_path))


def _member_by_sid(root: etree._Element, sid: str) -> etree._Element:
    return root.xpath("./Scopes/Scope/Role/Member[@sid=$sid]", sid=sid)[0]


def test_member_user_resolution_matches_checked_in_xslt_and_golden(tmp_path):
    python_output = _python_output()
    xslt_output = _xslt_output(tmp_path)
    canonicalize = lambda tree: GoldenValidator._canonical_xml(
        tree, "authstore_normalized"
    )

    assert canonicalize(python_output) == canonicalize(xslt_output)

    golden_path = FIXTURE_DIR / "golden" / "authstore_normalized.xml"
    assert canonicalize(xslt_output) == canonicalize(etree.parse(str(golden_path)))


def test_identity_precedes_security_id_and_emits_all_identity_matches():
    root = _python_output().getroot()
    member = _member_by_sid(root, "shared-sid")

    assert member.get("type") == "unknown"
    assert [user.get("id") for user in member.findall("User")] == [
        "identity-first",
        "identity-second",
    ]
    assert member.xpath("./User/Identity/@name") == [
        r"DOMAIN\first",
        r"DOMAIN\second",
    ]
    assert member.xpath("./User/Identity/text()") == ["shared-sid", "shared-sid"]
    assert member.xpath("./User/Identity/@sid") == []


def test_security_id_matching_preserves_exact_source_text_and_attributes():
    root = _python_output().getroot()
    unresolved_member = _member_by_sid(root, "whitespace-sid")
    unresolved_user = unresolved_member.find("User")
    assert unresolved_user is not None
    assert unresolved_user.attrib == {}
    assert unresolved_user.text == "whitespace-sid"

    member = _member_by_sid(root, "  whitespace-sid  ")
    user = member.find("User")
    assert member.get("type") == "unknown"
    assert user is not None
    assert user.attrib == {
        "name": "Whitespace Security ID",
        "id": "security-whitespace",
        "hash": "hash-whitespace",
    }
    assert user.text == "  whitespace-sid  "
    assert user.find("Identity") is None


def test_well_known_sid_output_uses_sid_as_user_name_and_account_as_identity_name():
    root = _python_output().getroot()
    account_names = {
        "S-1-5-32-544": r".\Administrators",
        "S-1-5-32-545": r".\Users",
        "S-1-5-32-546": r".\Guests",
        "S-1-5-32-547": r".\Power Users",
        "S-1-5-11": "Authenticated Users",
    }

    for sid, account_name in account_names.items():
        member = _member_by_sid(root, sid)
        user = member.find("User")
        assert user is not None
        assert user.attrib == {"name": sid}
        assert user.find("Identity").attrib == {"name": account_name}
        assert user.find("Identity").text == sid
        assert user.find("Identity").get("sid") is None


def test_unresolved_and_xslt_unmatched_domain_rids_use_sid_text_fallback():
    root = _python_output().getroot()
    for sid in ("unresolved-sid", "S-1-5-21-111-222-333-500"):
        member = _member_by_sid(root, sid)
        user = member.find("User")
        assert user is not None
        assert user.attrib == {}
        assert user.text == sid
        assert len(user) == 0


def test_member_sid_and_type_match_xslt_contains_and_whitespace_rules():
    root = _python_output().getroot()
    member = _member_by_sid(root, "prefix-S-1-9-42")
    assert member.attrib == {"sid": "prefix-S-1-9-42", "type": "ampla"}


def test_resolve_user_uses_identity_then_security_id_precedence():
    normalizer = AuthstoreNormalizer(etree.ElementTree(etree.Element("AzAdminManager")))
    project_users = etree.parse(str(FIXTURE_DIR / "project_security.xml")).xpath(
        "./Users/User"
    )

    resolved = normalizer.resolve_user(
        "shared-sid",
        {
            "shared-sid": next(
                user for user in project_users if user.get("id") == "security-id"
            ),
            "other-key": next(
                user for user in project_users if user.get("id") == "identity-first"
            ),
        },
    )
    assert resolved is not None
    assert resolved.get("id") == "identity-first"
