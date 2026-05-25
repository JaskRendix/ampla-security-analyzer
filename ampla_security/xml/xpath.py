from lxml.etree import _Element


def find_nodes(root: _Element, xpath: str) -> list[_Element]:
    return root.xpath(xpath)


def find_first(root: _Element, xpath: str) -> _Element | None:
    matches: list[_Element] = root.xpath(xpath)
    return matches[0] if matches else None


def find_text(root: _Element, xpath: str) -> str | None:
    node = find_first(root, xpath)
    return node.text if node is not None else None


def boolean(root: _Element, xpath: str) -> bool:
    return bool(root.xpath(xpath))
