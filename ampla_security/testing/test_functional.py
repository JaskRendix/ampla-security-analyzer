"""
Comprehensive functional test suite for Ampla Security Python engine.

Tests core normalization, rule application, and security analysis functionality.
"""

import pytest
from lxml import etree

from ampla_security.normalization.authstore_normalizer import AuthstoreNormalizer
from ampla_security.normalization.project_normalizer import ProjectNormalizer
from ampla_security.normalization.project_security_extractor import (
    ProjectSecurityExtractor,
)
from ampla_security.utils.hashing import sha1


class TestProjectNormalization:
    """Test project normalization functionality."""

    def test_normalize_project_structure(self):
        """Test that projects are normalized to expected structure."""
        xml_str = """<?xml version="1.0"?>
<Ampla name="TestProject">
    <Reference id="ref1" name="Citect.Ampla.StandardItems" version="4.4"/>
    <Item id="item1" name="TestItem">
        <Property name="TestProp">TestValue</Property>
    </Item>
</Ampla>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        normalizer = ProjectNormalizer(tree)
        result = normalizer.normalize()

        assert result.getroot().tag == "Project"
        assert len(result.getroot().xpath("./Properties")) == 1
        assert len(result.getroot().xpath(".//Item[@id='item1']")) == 1

    def test_add_hash_attributes(self):
        """Test that hash attributes are added to items."""
        xml_str = """<?xml version="1.0"?>
<Ampla name="TestProject">
    <Reference id="ref1" name="Citect.Ampla.StandardItems" version="4.4"/>
    <Item id="item1" name="TestItem">
        <Property name="TestProp">TestValue</Property>
    </Item>
</Ampla>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        normalizer = ProjectNormalizer(tree)
        result = normalizer.normalize()

        item = result.getroot().xpath(".//Item[@id='item1']")[0]
        assert item.get("hash") == sha1("item1")

    def test_add_display_order(self):
        """Test that DisplayOrder property is added."""
        xml_str = """<?xml version="1.0"?>
<Ampla name="TestProject">
    <Reference id="ref1" name="Citect.Ampla.StandardItems" version="4.4"/>
    <Item id="item1" name="TestItem">
        <Property name="TestProp">TestValue</Property>
    </Item>
</Ampla>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        normalizer = ProjectNormalizer(tree)
        result = normalizer.normalize()

        item = result.getroot().xpath(".//Item[@id='item1']")[0]
        display_order = item.xpath("Property[@name='DisplayOrder']")
        assert len(display_order) == 1
        assert display_order[0].text == "0"

    def test_exclude_properties(self):
        """Test that excluded properties are removed."""
        xml_str = """<?xml version="1.0"?>
<Ampla name="TestProject">
    <Reference id="ref1" name="Citect.Ampla.StandardItems" version="4.4"/>
    <Item id="item1" name="TestItem">
        <Property name="TestProp">TestValue</Property>
        <Property name="RunState">Running</Property>
        <Property name="DataSource">SomeSource</Property>
    </Item>
</Ampla>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        normalizer = ProjectNormalizer(tree)
        result = normalizer.normalize()

        item = result.getroot().xpath(".//Item[@id='item1']")[0]
        assert len(item.xpath("Property[@name='RunState']")) == 0
        assert len(item.xpath("Property[@name='DataSource']")) == 0
        assert len(item.xpath("Property[@name='TestProp']")) == 1


class TestProjectSecurityExtraction:
    """Test project security extraction functionality."""

    def test_extract_users(self):
        """Test that User items are extracted."""
        xml_str = """<?xml version="1.0"?>
<Project>
    <Item id="user1" name="TestUser" type="Citect.Ampla.StandardItems.User">
        <Property name="DisplayOrder">1</Property>
    </Item>
    <Item id="item2" name="TestItem" type="OtherType">
    </Item>
</Project>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        extractor = ProjectSecurityExtractor(tree)
        result = extractor.extract()

        users = result.getroot().xpath("./Users/User")
        assert len(users) == 1
        assert users[0].get("id") == "user1"

    def test_extract_scopes(self):
        """Test that scopes are extracted from items with InheritPermissions=False."""
        xml_str = """<?xml version="1.0"?>
<Project>
    <Item id="scope1" name="TestScope">
        <Property name="InheritPermissions">False</Property>
    </Item>
    <Item id="item2" name="TestItem">
        <Property name="InheritPermissions">True</Property>
    </Item>
</Project>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        extractor = ProjectSecurityExtractor(tree)
        result = extractor.extract()

        scopes = result.getroot().xpath("./Scopes/Scope")
        assert [scope.get("scopeId") for scope in scopes] == [
            "00000000-0000-0000-0000-000000000000",
            "scope1",
        ]


class TestAuthStoreNormalization:
    """Test AuthStore normalization functionality."""

    def test_normalize_authstore_structure(self):
        """Test that AuthStore is normalized."""
        xml_str = """<?xml version="1.0"?>
<AzAdminManager>
    <AzApplication Name="TestApp">
    </AzApplication>
</AzAdminManager>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        normalizer = AuthstoreNormalizer(tree)
        result = normalizer.normalize()

        assert result.getroot().tag == "Security"
        assert [child.tag for child in result.getroot()] == [
            "Operations",
            "RoleDefinitions",
            "Scopes",
            "Users",
        ]

    def test_parse_identity_property(self):
        """Test that Identity properties are correctly parsed."""
        tree = etree.ElementTree(
            etree.fromstring(
                b'<Project><Item id="user" name="Alice" '
                b'type="Citect.Ampla.StandardItems.User"><Property '
                b'name="Identity">DOMAIN\\user|S-1-5-21-123-456-789|OTHER'
                b"</Property></Item></Project>"
            )
        )
        result = ProjectSecurityExtractor(tree).extract()

        identity = result.xpath(
            "./Users/User[@id='user']/Property[@name='Identity']/Identity"
        )[0]
        assert identity.get("name") == "DOMAIN\\user"
        assert identity.get("sid") == "S-1-5-21-123-456-789"
        assert identity.text == "DOMAIN\\user|S-1-5-21-123-456-789|OTHER"


class TestSpecializedTransforms:
    """Test specialized project transforms from Phase D."""

    def test_cycle_manager_cycles(self):
        """Test CycleManager Cycles transformation."""
        xml_str = """<?xml version="1.0"?>
<Ampla name="TestProject">
    <Reference id="ref1" name="Citect.Ampla.StandardItems" version="4.4"/>
    <Reference id="ref2" name="Citect.Ampla.General.Server" version="4.4"/>
    <Item id="mgr1" name="CycleMgr" type="Citect.Ampla.General.Server.RecordStates.CycleManager">
        <Property name="Cycles">
            <Item>Cycle1</Item>
            <Item>Cycle2</Item>
        </Property>
    </Item>
</Ampla>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        normalizer = ProjectNormalizer(tree)
        result = normalizer.normalize()

        cycles_prop = result.getroot().xpath(
            ".//Item[@id='mgr1']/Property[@name='Cycles']"
        )
        assert len(cycles_prop) == 1
        item_links = cycles_prop[0].xpath("./ItemLink")
        assert [link.get("absolutePath") for link in item_links] == [
            "Cycle1",
            "Cycle2",
        ]

    def test_resolver_defaults(self):
        """Test Resolver default properties."""
        xml_str = """<?xml version="1.0"?>
<Ampla name="TestProject">
    <Reference id="ref1" name="Citect.Ampla.StandardItems" version="4.4"/>
    <Reference id="ref3" name="Citect.Ampla.Metrics.Server" version="4.4"/>
    <Item id="res1" name="Resolver1" type="Citect.Ampla.Metrics.Server.Resolvers.Resolver">
        <Property name="Name">TestResolver</Property>
    </Item>
</Ampla>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        normalizer = ProjectNormalizer(tree)
        result = normalizer.normalize()

        item = result.getroot().xpath(".//Item[@id='res1']")[0]
        action = item.xpath("Property[@name='Action']")
        resolver_op = item.xpath("Property[@name='ResolverOperation']")

        assert [prop.text for prop in action] == ["Module"]
        assert [prop.text for prop in resolver_op] == ["Sum"]

    def test_user_authentication_default(self):
        """Test User default Authentication property."""
        xml_str = """<?xml version="1.0"?>
<Ampla name="TestProject">
    <Reference id="ref1" name="Citect.Ampla.StandardItems" version="4.4"/>
    <Item id="user1" name="TestUser" type="Citect.Ampla.StandardItems.User">
        <Property name="Name">TestUser</Property>
    </Item>
</Ampla>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        normalizer = ProjectNormalizer(tree)
        result = normalizer.normalize()

        item = result.getroot().xpath(".//Item[@id='user1']")[0]
        auth = item.xpath("Property[@name='Authentication']")
        assert [prop.text for prop in auth] == ["WindowsIntegrated"]


class TestEndToEndPipeline:
    """Test complete pipeline execution."""

    def test_pipeline_produces_valid_xml(self):
        """Test that pipeline produces valid XML output."""
        xml_str = """<?xml version="1.0"?>
<Ampla name="TestProject">
    <Reference id="ref1" name="Citect.Ampla.StandardItems" version="4.4"/>
    <Item id="item1" name="TestItem">
        <Property name="TestProp">TestValue</Property>
    </Item>
</Ampla>"""
        tree = etree.ElementTree(etree.fromstring(xml_str.encode()))
        normalizer = ProjectNormalizer(tree)
        result = normalizer.normalize()

        assert result.getroot().tag == "Project"
        assert result.xpath("./Properties/ProjectProperty[@name='name']/text()") == [
            "TestProject"
        ]
        assert result.xpath(
            ".//Item[@id='item1']/Property[@name='TestProp']/text()"
        ) == ["TestValue"]

    def test_pipeline_deterministic(self):
        """Test that pipeline produces deterministic output."""
        xml_str = """<?xml version="1.0"?>
<Ampla name="TestProject">
    <Reference id="ref1" name="Citect.Ampla.StandardItems" version="4.4"/>
    <Item id="item1" name="TestItem">
        <Property name="TestProp">TestValue</Property>
    </Item>
</Ampla>"""

        # Run twice
        tree1 = etree.ElementTree(etree.fromstring(xml_str.encode()))
        result1 = ProjectNormalizer(tree1).normalize()

        tree2 = etree.ElementTree(etree.fromstring(xml_str.encode()))
        result2 = ProjectNormalizer(tree2).normalize()

        assert etree.tostring(result1, method="c14n") == etree.tostring(
            result2, method="c14n"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
