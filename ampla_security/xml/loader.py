from pathlib import Path

from lxml import etree
from lxml.etree import _ElementTree


def load_xml(path: str | Path) -> _ElementTree:
    return etree.parse(str(path))
