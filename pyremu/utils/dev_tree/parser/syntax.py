# Copyright (c) 2019, Nordic Semiconductor
# SPDX-License-Identifier: BSD-3-Clause
#
# 本文件由 Zephyr Project 的 python-devicetree 包中的 dtlib.py 拆分而来,
# 并做了模块切分、标识符更名与静态检查所需的少量改写.
# 版权声明与许可条款见同目录下的 LICENSE.

"""设备树的语法分析 — 记号序列到节点树, 以及树的后续整理."""

import collections
from collections.abc import Iterable
import os
import re
from typing import Optional, TYPE_CHECKING

from pyremu.utils.dev_tree.parser.lexer import LexerOps
from pyremu.utils.dev_tree.parser.model import (
    DTError,
    err,
    MarkerType,
    N_BYTES_TO_TYPE,
    Node,
    Property,
)
from pyremu.utils.dev_tree.parser.tokens import (
    FileStackElt,
    LEXER_DEFAULT,
    nodename_chars,
    Token,
    TokenId,
)


class DT(LexerOps):
    """
    Represents a devicetree parsed from a .dts file (or from many files, if the
    .dts file /include/s other files). Creating many instances of this class is
    fine. The library has no global state.

    These attributes are available on DT instances:

    root:
      A Node instance representing the root (/) node.

    alias2node:
      A dictionary that maps maps alias strings (from /aliases) to Node
      instances

    label2node:
      A dictionary that maps each node label (a string) to the Node instance
      for the node.

    label2prop:
      A dictionary that maps each property label (a string) to a Property
      instance.

    label2prop_offset:
      A dictionary that maps each label (a string) within a property value
      (e.g., 'x = label_1: < 1 label2: 2 >;') to a (prop, offset) tuple, where
      'prop' is a Property instance and 'offset' the byte offset (0 for label_1
      and 4 for label_2 in the example).

    phandle2node:
      A dictionary that maps each phandle (a number) to a Node instance.

    memreserves:
      A list of (labels, address, length) tuples for the /memreserve/s in the
      .dts file, in the same order as they appear in the file.

      'labels' is a possibly empty set with all labels preceding the memreserve
      (e.g., 'label1: label2: /memreserve/ ...'). 'address' and 'length' are
      numbers.

    filename:
      The filename passed to the DT constructor.
    """

    #
    # Public interface
    #

    def __init__(
        self,
        filename: Optional[str],
        include_path: Iterable[str] = (),
        force: bool = False,
        base_dir: Optional[str] = None,
    ):
        """
        Parses a DTS file to create a DT instance. Raises OSError if 'filename'
        can't be opened, and DTError for any parse errors.

        filename:
          Path to the .dts file to parse. (If None, an empty devicetree
          is created; this is unlikely to be what you want.)

        include_path:
          An iterable (e.g. list or tuple) containing paths to search for
          /include/d and /incbin/'d files. By default, files are only looked up
          relative to the .dts file that contains the /include/ or /incbin/.

        force:
          Try not to raise DTError even if the input tree has errors.
          For experimental use; results not guaranteed.

        base_dir:
          Path to the directory that is to be used as the reference for
          the generated relative paths in comments. When not provided, the
          current working directory is used.
        """
        # Remember to update __deepcopy__() if you change this.

        self._root: Optional[Node] = None
        self.alias2node: dict[str, Node] = {}
        self.label2node: dict[str, Node] = {}
        self.label2prop: dict[str, Property] = {}
        self.label2prop_offset: dict[str, tuple[Property, int]] = {}
        self.phandle2node: dict[int, Node] = {}
        self.memreserves: list[tuple[set[str], int, int]] = []
        self.filename = filename

        self._force = force
        self._base_dir = base_dir or os.getcwd()

        if filename is not None:
            self._parse_file(filename, include_path)
        else:
            self._include_path: list[str] = []

    @property
    def root(self) -> Node:
        """
        See the class documentation.
        """
        # This is necessary because mypy can't tell that we never
        # treat self._root as a non-None value until it's initialized
        # properly in _parse_dt().
        return self._root  # type: ignore

    def get_node(self, path: str) -> Node:
        """
        Returns the Node instance for the node with path or alias 'path' (a
        string). Raises DTError if the path or alias doesn't exist.

        For example, both dt.get_node("/foo/bar") and dt.get_node("bar-alias")
        will return the 'bar' node below:

          /dts-v1/;

          / {
                  foo {
                          bar_label: bar {
                                  baz {
                                  };
                          };
                  };

                  aliases {
                          bar-alias = &bar-label;
                  };
          };

        Fetching subnodes via aliases is supported:
        dt.get_node("bar-alias/baz") returns the 'baz' node.
        """
        if path.startswith("/"):
            return _root_and_path_to_node(self.root, path, path)

        # Path does not start with '/'. First component must be an alias.
        alias, _, rest = path.partition("/")
        if alias not in self.alias2node:
            err(
                f"no alias '{alias}' found -- did you forget the leading '/' in the node path?"
            )

        return _root_and_path_to_node(self.alias2node[alias], rest, path)

    def has_node(self, path: str) -> bool:
        """
        Returns True if the path or alias 'path' exists. See DT.get_node().
        """
        try:
            self.get_node(path)
            return True
        except DTError:
            return False

    def move_node(self, node: Node, new_path: str):
        """
        Move a node 'node' to a new path 'new_path'. The entire subtree
        rooted at 'node' is moved along with it.

        You cannot move the root node or provide a 'new_path' value
        where a node already exists. This method raises an exception
        in both cases.

        As a restriction on the current implementation, the parent node
        of the new path must exist.
        """
        if node is self.root:
            err("the root node can't be moved")

        if self.has_node(new_path):
            err(f"can't move '{node.path}' to '{new_path}': destination node exists")

        if not new_path.startswith("/"):
            err(f"path '{new_path}' doesn't start with '/'")

        for component in new_path.split("/"):
            for char in component:
                if char not in nodename_chars:
                    err(f"new path '{new_path}': bad character '{char}'")

        old_name = node.name
        old_path = node.path

        new_parent_path, _, new_name = new_path.rpartition("/")
        if new_parent_path == "":
            # '/foo'.rpartition('/') is ('', '/', 'foo').
            new_parent_path = "/"
        if not self.has_node(new_parent_path):
            err(
                f"can't move '{old_path}' to '{new_path}': "
                f"parent node '{new_parent_path}' doesn't exist"
            )
        new_parent = self.get_node(new_parent_path)
        if TYPE_CHECKING:
            assert new_parent is not None
            assert node.parent is not None

        del node.parent.nodes[old_name]
        node._name = new_name
        node.parent = new_parent
        new_parent.nodes[new_name] = node

    def node_iter(self) -> Iterable[Node]:
        """
        Returns a generator for iterating over all nodes in the devicetree.

        For example, this will print the name of each node that has a property
        called 'foo':

          for node in dt.node_iter():
              if "foo" in node.props:
                  print(node.name)
        """
        yield from self.root.node_iter()

    def __str__(self):
        """
        Returns a DTS representation of the devicetree. Called automatically if
        the DT instance is print()ed.
        """
        s = "/dts-v1/;\n"

        if self.memreserves:
            s += "\n"
            for labels, address, offset in self.memreserves:
                # List the labels in a consistent order to help with testing
                for label in labels:
                    s += f"{label}: "
                s += f"/memreserve/ {address:#018x} {offset:#018x};\n"

        return s + str(self.root)

    def __repr__(self):
        """
        Returns some information about the DT instance. Called automatically if
        the DT instance is evaluated.
        """
        if self.filename:
            return f"DT(filename='{self.filename}', include_path={self._include_path})"
        return super().__repr__()

    def __deepcopy__(self, memo):
        """
        Implements support for the standard library copy.deepcopy()
        function on DT instances.
        """

        # We need a new DT, obviously. Make a new, empty one.
        ret = DT(None, (), self._force, self._base_dir)

        # Now allocate new Node objects for every node in self, to use
        # in the new DT. Set their parents to None for now and leave
        # them without any properties. We will recursively initialize
        # copies of parents before copies of children next.
        path2node_copy = {
            node.path: Node(node.name, None, ret, node.filename, node.lineno)
            for node in self.node_iter()
        }

        # Point each copy of a node to the copy of its parent and set up
        # copies of each property.
        #
        # Share data when possible. For example, Property.value has
        # type 'bytes', which is immutable. We therefore don't need a
        # copy and can just point to the original data.

        for node in self.node_iter():
            node_copy = path2node_copy[node.path]

            parent = node.parent
            if parent is not None:
                node_copy.parent = path2node_copy[parent.path]

            prop_name2prop_copy = {
                prop.name: Property(node_copy, prop.name) for prop in node.props.values()
            }
            for prop_name, prop_copy in prop_name2prop_copy.items():
                prop = node.props[prop_name]
                prop_copy.value = prop.value
                prop_copy.labels = prop.labels[:]
                prop_copy.offset_labels = prop.offset_labels.copy()
                prop_copy._label_offset_lst = prop._label_offset_lst[:]
                prop_copy._markers = [marker[:] for marker in prop._markers]
                prop_copy._signed_cell_offsets = prop._signed_cell_offsets.copy()
                prop_copy.filename = prop.filename
                prop_copy.lineno = prop.lineno
            node_copy.props = prop_name2prop_copy

            node_copy.nodes = {
                child_name: path2node_copy[child_node.path]
                for child_name, child_node in node.nodes.items()
            }

            node_copy.labels = node.labels[:]

            node_copy._omit_if_no_ref = node._omit_if_no_ref
            node_copy._is_referenced = node._is_referenced

        # The copied nodes and properties are initialized, so
        # we can finish initializing the copied DT object now.

        ret._root = path2node_copy["/"]

        def copy_node_lookup_table(attr_name):
            original = getattr(self, attr_name)
            copy = {key: path2node_copy[original[key].path] for key in original}
            setattr(ret, attr_name, copy)

        copy_node_lookup_table("alias2node")
        copy_node_lookup_table("label2node")
        copy_node_lookup_table("phandle2node")

        ret_label2prop = {}
        for label, prop in self.label2prop.items():
            node_copy = path2node_copy[prop.node.path]
            prop_copy = node_copy.props[prop.name]
            ret_label2prop[label] = prop_copy
        ret.label2prop = ret_label2prop

        ret_label2prop_offset = {}
        for label, prop_offset in self.label2prop_offset.items():
            prop, offset = prop_offset
            node_copy = path2node_copy[prop.node.path]
            prop_copy = node_copy.props[prop.name]
            ret_label2prop_offset[label] = (prop_copy, offset)
        ret.label2prop_offset = ret_label2prop_offset

        ret.memreserves = [
            (set(memreserve[0]), memreserve[1], memreserve[2])
            for memreserve in self.memreserves
        ]

        ret.filename = self.filename

        return ret

    #
    # Parsing
    #

    @classmethod
    def from_text(cls, contents: str, filename: str = "<text>") -> "DT":
        """由 DTS 源文本构造, 不读取文件."""
        ret = cls(None)
        ret.filename = filename
        ret._file_contents = contents
        ret._parse_contents()
        return ret

    def _parse_file(self, filename: str, include_path: Iterable[str]):
        self._include_path = list(include_path)

        with open(filename, encoding="utf-8") as f:
            self._file_contents = f.read()

        self._parse_contents()

    def _parse_contents(self):
        self._tok_i = self._tok_end_i = 0
        self._filestack: list[FileStackElt] = []
        self._lexer_state: int = LEXER_DEFAULT
        self._saved_token: Optional[Token] = None
        self._lineno: int = 1

        self._parse_header()
        self._parse_memreserves()
        self._parse_dt()
        self._register_phandles()
        self._fixup_props()
        self._register_aliases()
        self._remove_unreferenced()
        self._register_labels()

    def _parse_header(self):
        # Parses /dts-v1/ (expected) and /plugin/ (unsupported) at the start of
        # files. There may be multiple /dts-v1/ at the start of a file.

        has_dts_v1 = False

        while self._peek_token().id == TokenId.DTS_V1:
            has_dts_v1 = True
            self._next_token()
            self._expect_token(";")
            # /plugin/ always comes after /dts-v1/
            if self._peek_token().id == TokenId.PLUGIN:
                self._parse_error("/plugin/ is not supported")

        if not has_dts_v1:
            self._parse_error("expected '/dts-v1/;' at start of file")

    def _parse_memreserves(self):
        # Parses /memreserve/, which appears after /dts-v1/

        while True:
            # Labels before /memreserve/
            labels = []
            while self._peek_token().id == TokenId.LABEL:
                _append_no_dup(labels, self._next_token().val)

            if self._peek_token().id == TokenId.MEMRESERVE:
                self._next_token()
                self.memreserves.append((labels, self._eval_prim(), self._eval_prim()))
                self._expect_token(";")
            elif labels:
                self._parse_error("expected /memreserve/ after labels at beginning of file")
            else:
                return

    def _parse_dt(self):  # noqa: PLR0912
        # Top-level parsing loop

        while True:
            tok = self._next_token()

            if tok.val == "/":
                # '/ { ... };', the root node
                if not self._root:
                    self._root = Node(
                        name="/",
                        parent=None,
                        dt=self,
                        filename=self.filename,
                        lineno=self._lineno,
                    )
                self._parse_node(self.root)

            elif tok.id in (TokenId.LABEL, TokenId.REF):
                # '&foo { ... };' or 'label: &foo { ... };'. The C tools only
                # support a single label here too.

                if tok.id == TokenId.LABEL:
                    label = tok.val
                    tok = self._next_token()
                    if tok.id != TokenId.REF:
                        self._parse_error("expected label reference (&foo)")
                else:
                    label = None

                try:
                    node = self._ref2node(tok.val)
                except DTError as e:
                    self._parse_error(e)
                self._parse_node(node)

                if label:
                    _append_no_dup(node.labels, label)

            elif tok.id == TokenId.DEL_NODE:
                self._next_ref2node()._del()
                self._expect_token(";")

            elif tok.id == TokenId.OMIT_IF_NO_REF:
                self._next_ref2node()._omit_if_no_ref = True
                self._expect_token(";")

            elif tok.id == TokenId.EOF:
                if not self._root:
                    self._parse_error("no root node defined")
                return

            else:
                self._parse_error("expected '/' or label reference (&foo)")

    def _parse_node(self, node):  # noqa: PLR0912
        # Parses the '{ ... };' part of 'node-name { ... };'.

        # We need to track which child nodes were defined in this set
        # of curly braces in order to reject duplicate node names.
        current_child_names = set()

        self._expect_token("{")
        while True:
            labels, omit_if_no_ref = self._parse_propnode_labels()
            tok = self._next_token()

            if tok.id == TokenId.PROPNODENAME:
                if self._peek_token().val == "{":
                    # '<tok> { ...', expect node

                    # Fetch the existing node if it already exists. This
                    # happens when overriding nodes.
                    child = node.nodes.get(tok.val)
                    if child:
                        if child.name in current_child_names:
                            self._parse_error(f"{child.path}: duplicate node name")
                    else:
                        child = Node(
                            name=tok.val,
                            parent=node,
                            dt=self,
                            filename=self.filename,
                            lineno=self._lineno,
                        )
                        current_child_names.add(tok.val)

                    for label in labels:
                        _append_no_dup(child.labels, label)

                    if omit_if_no_ref:
                        child._omit_if_no_ref = True

                    node.nodes[child.name] = child
                    self._parse_node(child)

                else:
                    # Not '<tok> { ...', expect property assignment

                    if omit_if_no_ref:
                        self._parse_error("/omit-if-no-ref/ can only be used on nodes")

                    prop = node._get_prop(tok.val)
                    prop.filename = self.filename
                    prop.lineno = self._lineno

                    if self._check_token("="):
                        self._parse_assignment(prop)
                    elif not self._check_token(";"):
                        # ';' is for an empty property, like 'foo;'
                        self._parse_error("expected '{', '=', or ';'")

                    for label in labels:
                        _append_no_dup(prop.labels, label)

            elif tok.id == TokenId.DEL_NODE:
                tok2 = self._next_token()
                if tok2.id != TokenId.PROPNODENAME:
                    self._parse_error("expected node name")
                if tok2.val in node.nodes:
                    node.nodes[tok2.val]._del()
                self._expect_token(";")

            elif tok.id == TokenId.DEL_PROP:
                tok2 = self._next_token()
                if tok2.id != TokenId.PROPNODENAME:
                    self._parse_error("expected property name")
                node.props.pop(tok2.val, None)
                self._expect_token(";")

            elif tok.val == "}":
                self._expect_token(";")
                return

            else:
                self._parse_error("expected node name, property name, or '}'")

    def _parse_propnode_labels(self):
        # _parse_node() helpers for parsing labels and /omit-if-no-ref/s before
        # nodes and properties. Returns a (<label list>, <omit-if-no-ref bool>)
        # tuple.

        labels = []
        omit_if_no_ref = False
        while True:
            tok = self._peek_token()
            if tok.id == TokenId.LABEL:
                _append_no_dup(labels, tok.val)
            elif tok.id == TokenId.OMIT_IF_NO_REF:
                omit_if_no_ref = True
            elif (labels or omit_if_no_ref) and tok.id != TokenId.PROPNODENAME:
                # Got something like 'foo: bar: }'
                self._parse_error("expected node or property name")
            else:
                return labels, omit_if_no_ref

            self._next_token()

    def _parse_assignment(self, prop):
        # Parses the right-hand side of property assignment
        #
        # prop:
        #   'Property' instance being assigned

        # Remove any old value, path/phandle references, and in-value labels,
        # in case the property value is being overridden
        prop.value = b""
        prop._markers = []
        prop._signed_cell_offsets = set()

        while True:
            # Parse labels before the value (e.g., '..., label: < 0 >')
            self._parse_value_labels(prop)

            tok = self._next_token()

            if tok.val == "<":
                self._parse_cells(prop, 4)

            elif tok.id == TokenId.BITS:
                n_bits = self._expect_num()
                if n_bits not in {8, 16, 32, 64}:
                    self._parse_error("expected 8, 16, 32, or 64")
                self._expect_token("<")
                self._parse_cells(prop, n_bits // 8)

            elif tok.val == "[":
                self._parse_bytes(prop)

            elif tok.id == TokenId.STRING:
                prop._add_marker(MarkerType.STRING)
                prop.value += self._unescape(tok.val.encode("utf-8")) + b"\0"

            elif tok.id == TokenId.REF:
                prop._add_marker(MarkerType.PATH, tok.val)

            elif tok.id == TokenId.INCBIN:
                self._parse_incbin(prop)

            else:
                self._parse_error("malformed value")

            # Parse labels after the value (e.g., '< 0 > label:, ...')
            self._parse_value_labels(prop)

            tok = self._next_token()
            if tok.val == ";":
                return
            if tok.val == ",":
                continue
            self._parse_error("expected ';' or ','")

    def _parse_cells(self, prop, n_bytes):
        # Parses '<...>'

        prop._add_marker(N_BYTES_TO_TYPE[n_bytes])

        while True:
            tok = self._peek_token()
            if tok.id == TokenId.REF:
                self._next_token()
                if n_bytes != 4:
                    self._parse_error(
                        "phandle references are only allowed in arrays with 32-bit elements"
                    )
                prop._add_marker(MarkerType.PHANDLE, tok.val)

            elif tok.id == TokenId.LABEL:
                prop._add_marker(MarkerType.LABEL, tok.val)
                self._next_token()

            elif self._check_token(">"):
                return

            else:
                # Literal value
                num = self._eval_prim()
                # A negative result can only come from a parenthesized
                # expression, e.g. (-1), which is the DTC-specified syntax for
                # negative constants.  Encode these directly as signed and
                # record the offset so callers can distinguish (-1) from
                # 0xFFFFFFFF.  Positive values are always encoded unsigned.
                if num < 0:
                    offset = len(prop.value)
                    try:
                        prop.value += num.to_bytes(n_bytes, "big", signed=True)
                    except OverflowError:
                        self._parse_error(f"{num} does not fit in {8 * n_bytes} bits")
                    prop._signed_cell_offsets.add(offset)
                else:
                    try:
                        prop.value += num.to_bytes(n_bytes, "big")
                    except OverflowError:
                        self._parse_error(f"{num} does not fit in {8 * n_bytes} bits")

    def _parse_bytes(self, prop):
        # Parses '[ ... ]'

        prop._add_marker(MarkerType.UINT8)

        while True:
            tok = self._next_token()
            if tok.id == TokenId.BYTE:
                prop.value += tok.val.to_bytes(1, "big")

            elif tok.id == TokenId.LABEL:
                prop._add_marker(MarkerType.LABEL, tok.val)

            elif tok.val == "]":
                return

            else:
                self._parse_error("expected two-digit byte or ']'")

    def _parse_incbin(self, prop):
        # Parses
        #
        #   /incbin/ ("filename")
        #
        # and
        #
        #   /incbin/ ("filename", <offset>, <size>)

        prop._add_marker(MarkerType.UINT8)

        self._expect_token("(")

        tok = self._next_token()
        if tok.id != TokenId.STRING:
            self._parse_error("expected quoted filename")
        filename = tok.val

        tok = self._next_token()
        if tok.val == ",":
            offset = self._eval_prim()
            self._expect_token(",")
            size = self._eval_prim()
            self._expect_token(")")
        else:
            if tok.val != ")":
                self._parse_error("expected ',' or ')'")
            offset = None

        try:
            with self._open(filename, "rb") as f:
                if offset is None:
                    prop.value += f.read()
                else:
                    f.seek(offset)
                    prop.value += f.read(size)
        except OSError as e:
            self._parse_error(f"could not read '{filename}': {e}")

    def _parse_value_labels(self, prop):
        # _parse_assignment() helper for parsing labels before/after each
        # comma-separated value

        while True:
            tok = self._peek_token()
            if tok.id != TokenId.LABEL:
                return
            prop._add_marker(MarkerType.LABEL, tok.val)
            self._next_token()

    def _node_phandle(self, node, src_prop):
        # Returns the phandle for Node 'node', creating a new phandle if the
        # node has no phandle, and fixing up the value for existing
        # self-referential phandles (which get set to b'\0\0\0\0' initially).
        # Self-referential phandles must be rewritten instead of recreated, so
        # that labels are preserved.

        if "phandle" in node.props:
            phandle_prop = node.props["phandle"]
        else:
            phandle_prop = Property(node, "phandle")
            phandle_prop._add_marker(MarkerType.UINT32)  # For displaying
            phandle_prop.value = b"\0\0\0\0"

        if phandle_prop.value == b"\0\0\0\0":
            phandle_i = 1
            while phandle_i in self.phandle2node:
                phandle_i += 1
            self.phandle2node[phandle_i] = node

            phandle_prop.filename = src_prop.filename
            phandle_prop.lineno = src_prop.lineno
            phandle_prop.value = phandle_i.to_bytes(4, "big")
            node.props["phandle"] = phandle_prop

        return phandle_prop.value

    # Expression evaluation

    def _eval_prim(self):
        tok = self._peek_token()
        if tok.id in (TokenId.NUM, TokenId.CHAR_LITERAL):
            return self._next_token().val

        tok = self._next_token()
        if tok.val != "(":
            self._parse_error("expected number or parenthesized expression")
        val = self._eval_ternary()
        self._expect_token(")")
        return val

    def _eval_ternary(self):
        val = self._eval_or()
        if self._check_token("?"):
            if_val = self._eval_ternary()
            self._expect_token(":")
            else_val = self._eval_ternary()
            return if_val if val else else_val
        return val

    def _eval_or(self):
        val = self._eval_and()
        while self._check_token("||"):
            val = 1 if self._eval_and() or val else 0
        return val

    def _eval_and(self):
        val = self._eval_bitor()
        while self._check_token("&&"):
            val = 1 if self._eval_bitor() and val else 0
        return val

    def _eval_bitor(self):
        val = self._eval_bitxor()
        while self._check_token("|"):
            val |= self._eval_bitxor()
        return val

    def _eval_bitxor(self):
        val = self._eval_bitand()
        while self._check_token("^"):
            val ^= self._eval_bitand()
        return val

    def _eval_bitand(self):
        val = self._eval_eq()
        while self._check_token("&"):
            val &= self._eval_eq()
        return val

    def _eval_eq(self):
        val = self._eval_rela()
        while True:
            if self._check_token("=="):
                val = 1 if val == self._eval_rela() else 0
            elif self._check_token("!="):
                val = 1 if val != self._eval_rela() else 0
            else:
                return val

    def _eval_rela(self):
        val = self._eval_shift()
        while True:
            if self._check_token("<"):
                val = 1 if val < self._eval_shift() else 0
            elif self._check_token(">"):
                val = 1 if val > self._eval_shift() else 0
            elif self._check_token("<="):
                val = 1 if val <= self._eval_shift() else 0
            elif self._check_token(">="):
                val = 1 if val >= self._eval_shift() else 0
            else:
                return val

    def _eval_shift(self):
        val = self._eval_add()
        while True:
            if self._check_token("<<"):
                val <<= self._eval_add()
            elif self._check_token(">>"):
                val >>= self._eval_add()
            else:
                return val

    def _eval_add(self):
        val = self._eval_mul()
        while True:
            if self._check_token("+"):
                val += self._eval_mul()
            elif self._check_token("-"):
                val -= self._eval_mul()
            else:
                return val

    def _eval_mul(self):
        val = self._eval_unary()
        while True:
            if self._check_token("*"):
                val *= self._eval_unary()
            elif self._check_token("/"):
                denom = self._eval_unary()
                if not denom:
                    self._parse_error("division by zero")
                val //= denom
            elif self._check_token("%"):
                denom = self._eval_unary()
                if not denom:
                    self._parse_error("division by zero")
                val %= denom
            else:
                return val

    def _eval_unary(self):
        if self._check_token("-"):
            return -self._eval_unary()
        if self._check_token("~"):
            return ~self._eval_unary()
        if self._check_token("!"):
            return 0 if self._eval_unary() else 1
        return self._eval_prim()

    def _next_ref2node(self):
        # Checks that the next token is a label/path reference and returns the
        # Node it points to. Only used during parsing, so uses _parse_error()
        # on errors to save some code in callers.

        label = self._next_token()
        if label.id != TokenId.REF:
            self._parse_error("expected label (&foo) or path (&{/foo/bar}) reference")
        try:
            return self._ref2node(label.val)
        except DTError as e:
            self._parse_error(e)

    def _ref2node(self, s):
        # Returns the Node the label/path reference 's' points to

        if s[0] == "{":
            # Path reference (&{/foo/bar})
            path = s[1:-1]
            if not path.startswith("/"):
                err(f"node path '{path}' does not start with '/'")
            # Will raise DTError if the path doesn't exist
            return _root_and_path_to_node(self.root, path, path)

        # Label reference (&foo).

        # label2node hasn't been filled in yet, and using it would get messy
        # when nodes are deleted
        for node in self.node_iter():
            if s in node.labels:
                return node

        err(f"undefined node label '{s}'")

    #
    # Post-processing
    #

    def _register_phandles(self):
        # Registers any manually-inserted phandle properties in
        # self.phandle2node, so that we can avoid allocating any phandles from
        # that set. Also checks the format of the phandles and does misc.
        # sanity checking.

        for node in self.node_iter():
            phandle = node.props.get("phandle")
            if phandle:
                if len(phandle.value) != 4:
                    err(
                        f"{node.path}: bad phandle length "
                        f"({len(phandle.value)}), expected 4 bytes"
                    )

                is_self_referential = False
                for marker in phandle._markers:
                    _, marker_type, ref = marker
                    if marker_type is MarkerType.PHANDLE:
                        # The phandle's value is itself a phandle reference
                        if self._ref2node(ref) is node:
                            # Alright to set a node's phandle equal to its own
                            # phandle. It'll force a new phandle to be
                            # allocated even if the node is otherwise
                            # unreferenced.
                            is_self_referential = True
                            break

                        err(f"{node.path}: {phandle.name} refers to another node")

                # Could put on else on the 'for' above too, but keep it
                # somewhat readable
                if not is_self_referential:
                    phandle_val = int.from_bytes(phandle.value, "big")

                    if phandle_val in {0, 0xFFFFFFFF}:
                        err(f"{node.path}: bad value {phandle_val:#010x} for {phandle.name}")

                    if phandle_val in self.phandle2node:
                        err(
                            f"{node.path}: duplicated phandle {phandle_val:#x} "
                            "(seen before at "
                            f"{self.phandle2node[phandle_val].path})"
                        )

                    self.phandle2node[phandle_val] = node

    def _fixup_props(self):
        # Fills in node path and phandle references in property values, and
        # registers labels within values. This must be done after parsing,
        # since forwards references are allowed and nodes and properties might
        # be deleted.

        for node in self.node_iter():
            # The tuple() avoids a 'dictionary changed size during iteration'
            # error
            for prop in tuple(node.props.values()):
                # 'prev_pos' and 'pos' are indices in the unpatched
                # property value. The result is built up in 'res'.
                prev_pos = 0
                res = b""

                for marker in prop._markers:
                    pos, marker_type, ref = marker

                    # Add data before the marker, reading from the unpatched
                    # property value
                    res += prop.value[prev_pos:pos]

                    # Fix the marker offset so that it's correct for the
                    # patched property value, for later (not used in this
                    # function). The offset might change due to path
                    # references, which expand to something like "/foo/bar".
                    marker[0] = len(res)

                    if marker_type is MarkerType.LABEL:
                        # This is a temporary format so that we can catch
                        # duplicate references. prop._label_offset_lst is changed
                        # to a dictionary that maps labels to offsets in
                        # _register_labels().
                        _append_no_dup(prop._label_offset_lst, (ref, len(res)))
                    elif marker_type in (MarkerType.PATH, MarkerType.PHANDLE):
                        # Path or phandle reference
                        try:
                            ref_node = self._ref2node(ref)
                        except DTError as e:
                            err(f"{prop.node.path}: {e}")

                        # For /omit-if-no-ref/
                        ref_node._is_referenced = True

                        if marker_type is MarkerType.PATH:
                            res += ref_node.path.encode("utf-8") + b"\0"
                        else:  # marker_type is PHANDLE
                            res += self._node_phandle(ref_node, prop)
                            # Skip over the dummy phandle placeholder
                            pos += 4

                    prev_pos = pos

                # Store the final fixed-up value. Add the data after the last
                # marker.
                prop.value = res + prop.value[prev_pos:]

    def _register_aliases(self):
        # Registers aliases from the /aliases node in self.alias2node. Also
        # checks the format of the alias properties.

        # We copy this to self.alias2node at the end to avoid get_node()
        # looking up paths via other aliases while verifying aliases
        alias2node = {}

        alias_re = re.compile("[0-9a-z-]+$")

        aliases = self.root.nodes.get("aliases")
        if aliases:
            for prop in aliases.props.values():
                if not alias_re.match(prop.name):
                    err(
                        f"/aliases: alias property name '{prop.name}' "
                        "should include only characters from [0-9a-z-]"
                    )

                # Property.to_path() checks that the node exists, has
                # the right type, etc. Swallow errors for invalid
                # aliases with self._force.
                try:
                    alias2node[prop.name] = prop.to_path()
                except DTError:
                    if self._force:
                        continue
                    raise

        self.alias2node = alias2node

    def _remove_unreferenced(self):
        # Removes any unreferenced nodes marked with /omit-if-no-ref/ from the
        # tree

        # tuple() is to avoid 'RuntimeError: dictionary changed size during
        # iteration' errors
        for node in tuple(self.node_iter()):
            if node._omit_if_no_ref and not node._is_referenced:
                node._del()

    def _register_labels(self):
        # Checks for duplicate labels and registers labels in label2node,
        # label2prop, and label2prop_offset

        label2things = collections.defaultdict(set)

        # Register all labels and the nodes/props they point to in label2things
        for node in self.node_iter():
            for label in node.labels:
                label2things[label].add(node)
                self.label2node[label] = node

            for prop in node.props.values():
                for label in prop.labels:
                    label2things[label].add(prop)
                    self.label2prop[label] = prop

                for label, offset in prop._label_offset_lst:
                    label2things[label].add((prop, offset))
                    self.label2prop_offset[label] = (prop, offset)

                # See _fixup_props()
                prop.offset_labels = dict(prop._label_offset_lst)

        for label, things in label2things.items():
            if len(things) > 1:
                strings = []
                for thing in things:
                    if isinstance(thing, Node):
                        strings.append(f"on {thing.path}")
                    elif isinstance(thing, Property):
                        strings.append(f"on property '{thing.name}' of node {thing.node.path}")
                    else:
                        # Label within property value
                        strings.append(
                            "in the value of property "
                            f"'{thing[0].name}' of node "
                            f"{thing[0].node.path}"
                        )

                # Give consistent error messages to help with testing
                strings.sort()

                err(f"Label '{label}' appears " + " and ".join(strings))


def _append_no_dup(lst, elm):
    # Appends 'elm' to 'lst', but only if it isn't already in 'lst'. Lets us
    # preserve order, which a set() doesn't.

    if elm not in lst:
        lst.append(elm)


def _root_and_path_to_node(cur, path, fullpath):
    # Returns the node pointed at by 'path', relative to the Node 'cur'. For
    # example, if 'cur' has path /foo/bar, and 'path' is "baz/qaz", then the
    # node with path /foo/bar/baz/qaz is returned. 'fullpath' is the path as
    # given in the .dts file, for error messages.

    for component in path.split("/"):
        # Collapse multiple / in a row, and allow a / at the end
        if not component:
            continue

        name, sep, address = component.partition("@")
        lookup = f"{name}@{address.lower()}" if sep else name

        if lookup not in cur.nodes:
            prefix = f"{name}@"
            names = [k for k in cur.nodes if k.startswith(prefix)]
            if len(names) == 1:
                cur = cur.nodes[names[0]]
            else:
                err(f"component '{component}' in path '{fullpath}' does not exist")
        else:
            cur = cur.nodes[lookup]

    return cur
