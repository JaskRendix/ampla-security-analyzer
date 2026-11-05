from pathlib import Path

from lxml import etree
from lxml.etree import _ElementTree


def load_xml(path: str | Path) -> _ElementTree:
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
    )

    return etree.parse(str(path), parser)
