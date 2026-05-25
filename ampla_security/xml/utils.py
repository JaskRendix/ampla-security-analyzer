from lxml import etree
from lxml.etree import _Element


def copy_node(node: _Element) -> _Element:
    return etree.fromstring(etree.tostring(node))


def remove_comments(node: _Element) -> None:
    for child in list(node):
        if isinstance(child, etree._Comment):
            node.remove(child)
        else:
            remove_comments(child)


def ensure_attribute(node: _Element, name: str, value: str | int | None) -> _Element:
    if not node.get(name) and value is not None:
        node.set(name, str(value))
    return node


def text_for(node: _Element) -> str:
    return node.text or ""
