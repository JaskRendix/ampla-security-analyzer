from __future__ import annotations

from lxml import etree
from lxml.etree import _Element, _ElementTree


class DocumentNormalizer:
    """
    Normalizes XML documents before security analysis.
    """

    def __init__(self, xml_tree: _ElementTree):
        self.tree: _ElementTree = xml_tree
        self.root: _Element = xml_tree.getroot()

    def normalize(self) -> _ElementTree:
        self._remove_comments(self.root)
        self._normalize_empty_text(self.root)
        return self.tree

    def _remove_comments(self, node: _Element) -> None:
        for child in list(node):
            if isinstance(child, etree._Comment):
                node.remove(child)
            else:
                self._remove_comments(child)

    def _normalize_empty_text(self, node: _Element) -> None:
        if node.text is not None and not node.text.strip():
            node.text = None
        if node.tail is not None and not node.tail.strip():
            node.tail = None

        for child in list(node):
            self._normalize_empty_text(child)
