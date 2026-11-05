from pathlib import Path

from lxml import etree

from ampla_security.normalization.project_normalizer import ProjectNormalizer

DESCRIPTOR_TYPE = (
    "Citect.Ampla.General.Common.FavoriteDescriptor," "Citect.Ampla.General.Common"
)
COLLECTION_TYPE = (
    "Citect.Ampla.General.Common.FavoriteDescriptorCollection,"
    "Citect.Ampla.General.Common"
)
PROJECT_XML = f"""\
<Ampla name="FavoritesParity">
  <Reference id="standard-items" name="Citect.Ampla.StandardItems" version="4.4.0"/>
  <Item id="user" name="Favorites" type="Citect.Ampla.StandardItems.User">
    <Property name="Home">
      <Property type="{DESCRIPTOR_TYPE}">
        <Property name="Name">Home shortcut</Property>
        <Property name="Module">Production</Property>
        <Property name="Location">Area.Home</Property>
        <Property name="LocationType">Home</Property>
      </Property>
      <Item type="{DESCRIPTOR_TYPE}">
        <Property name="LocationType">Home</Property>
      </Item>
    </Property>
    <Property name="Favorites">
      <Property type="{COLLECTION_TYPE}">
        <Property name="Name">My favorites</Property>
        <Item type="{DESCRIPTOR_TYPE}">
          <Property name="Name">Plant overview</Property>
          <Property name="Module">Overview</Property>
          <Property name="Filter">Status=Active</Property>
          <Property name="Location">Plant</Property>
          <Property name="LocationType">Favorite</Property>
          <Property name="Recurse">True</Property>
          <Property name="ViewName">Summary</Property>
        </Item>
        <Item type="{COLLECTION_TYPE}">
          <Property name="Name">Nested group</Property>
          <Item type="{DESCRIPTOR_TYPE}">
            <Property name="Module">Trend</Property>
            <Property name="Location">Plant.Area</Property>
            <Property name="LocationType">Favorite</Property>
          </Item>
          <Item type="{DESCRIPTOR_TYPE}">
            <Property name="Name">No location</Property>
            <Property name="LocationType">Corrupt</Property>
          </Item>
        </Item>
      </Property>
    </Property>
    <Property name="EmptyFavorites"/>
  </Item>
</Ampla>
"""

STYLESHEET = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "StyleSheets"
    / "Project.Normalize.xslt"
)


def _canonical_xml(node: etree._Element) -> bytes:
    for element in node.iter():
        element.attrib.pop("hash", None)
        element.attrib.pop("fullName", None)
        if element.text is not None and not element.text.strip():
            element.text = None
        if element.tail is not None and not element.tail.strip():
            element.tail = None
    return etree.tostring(node, method="c14n")


def _xslt_output() -> etree._ElementTree:
    source = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    transform = etree.XSLT(etree.parse(str(STYLESHEET)))
    output = transform(source)
    return etree.ElementTree(etree.fromstring(etree.tostring(output)))


def test_home_and_favorites_output_match_xslt():
    source = etree.ElementTree(etree.fromstring(PROJECT_XML.encode()))
    python_output = ProjectNormalizer(source).normalize()
    xslt_output = _xslt_output()

    for property_name in ("Home", "Favorites", "EmptyFavorites"):
        python_property = python_output.xpath(
            ".//Item[@id='user']/Property[@name=$name]", name=property_name
        )[0]
        xslt_property = xslt_output.xpath(
            ".//Item[@id='user']/Property[@name=$name]", name=property_name
        )[0]
        assert _canonical_xml(python_property) == _canonical_xml(xslt_property)

    home = python_output.xpath(".//Item[@id='user']/Property[@name='Home']")[0]
    assert home.xpath("./text/text()") == ["{2 Favourite(s)}"]
    assert home.xpath("./Favorite/@name") == ["Home shortcut"]

    favorites = python_output.xpath(".//Item[@id='user']/Property[@name='Favorites']")[
        0
    ]
    assert favorites.xpath("./text/@isCorrupt") == ["true"]
    assert favorites.xpath("./text/text()") == ["{3 Favourite(s)}"]
    assert favorites.xpath("./Favorites/@name") == ["My favorites"]
    assert favorites.xpath("./Favorites/Favorites/@name") == ["Nested group"]
    assert favorites.xpath("./Favorites/Favorite/@name") == ["Plant overview"]
    assert favorites.xpath("./Favorites/Favorite/@module") == ["Overview"]
    assert favorites.xpath("./Favorites/Favorite/@filter") == ["Status=Active"]
    assert favorites.xpath("./Favorites/Favorite/@location") == ["Plant"]
    assert favorites.xpath("./Favorites/Favorite/@recurse") == ["True"]
    assert favorites.xpath("./Favorites/Favorite/@view") == ["Summary"]
    nested_favorite = favorites.xpath("./Favorites/Favorites/Favorite")[0]
    assert nested_favorite.attrib == {
        "name": "",
        "module": "Trend",
        "location": "Plant.Area",
    }


def test_empty_favorites_uses_literal_text_not_a_text_element():
    xml = f"""\
    <Ampla>
      <Item id="item" name="Item">
        <Property name="Favorites">
          <Property type="{COLLECTION_TYPE}">
            <Property name="Name">Empty</Property>
          </Property>
        </Property>
      </Item>
    </Ampla>
    """
    source = etree.ElementTree(etree.fromstring(xml.encode()))
    normalized = ProjectNormalizer(source).normalize()
    favorites = normalized.xpath(".//Item[@id='item']/Property[@name='Favorites']")[0]

    assert favorites.text == "{0 Favorite(s)}"
    assert list(favorites) == []
