# Copyright (c) 2019, Nordic Semiconductor
# SPDX-License-Identifier: BSD-3-Clause
#
# 本文件由 Zephyr Project 的 python-devicetree 包中的 dtlib.py 拆分而来,
# 并做了模块切分、标识符更名与静态检查所需的少量改写.
# 版权声明与许可条款见同目录下的 LICENSE.

"""设备树的节点、属性与类型 — 解析结果的数据模型."""

from collections.abc import Iterable
import enum
import os
import textwrap
from typing import Any, NoReturn, Optional, TYPE_CHECKING

from pyremu.utils.dev_tree.parser.tokens import nodename_chars

if TYPE_CHECKING:
    from pyremu.utils.dev_tree.parser.syntax import DT


class DTError(Exception):
    "Exception raised for devicetree-related errors"


class Node:
    r"""
    Represents a node in the devicetree ('node-name { ... };').

    These attributes are available on Node instances:

    name:
      The name of the node (a string).

    filename:
      The name of the .dts file where the node is defined

    lineno:
      The line number in the .dts file where the node starts.

    unit_addr:
      The portion after the '@' in the node's name, or the empty string if the
      name has no '@' in it.

      Note that this is a string. Run int(node.unit_addr, 16) to get an
      integer.

    props:
      A dict that maps the properties defined on the node to
      their values. 'props' is indexed by property name (a string), and values
      are Property objects.

      To convert property values to Python numbers or strings, use
      dtlib.to_num(), dtlib.to_nums(), or dtlib.to_string().

      Property values are represented as 'bytes' arrays to support the full
      generality of DTS, which allows assignments like

        x = "foo", < 0x12345678 >, [ 9A ];

      This gives x the value b"foo\0\x12\x34\x56\x78\x9A". Numbers in DTS are
      stored in big-endian format.

    nodes:
      A dict containing the subnodes of the node, indexed by name.

    labels:
      A list with all labels pointing to the node, in the same order as the
      labels appear, but with duplicates removed.

      'label_1: label_2: node { ... };' gives 'labels' the value
      ["label_1", "label_2"].

    parent:
      The parent Node of the node. 'None' for the root node.

    path:
      The path to the node as a string, e.g. "/foo/bar".

    dt:
      The DT instance this node belongs to.
    """

    #
    # Public interface
    #

    def __init__(
        self,
        name: str,
        parent: Optional["Node"],
        dt: "DT",
        filename: str,
        lineno: int,
    ):
        """
        Node constructor. Not meant to be called directly by clients.
        """
        # Remember to update DT.__deepcopy__() if you change this.

        self._name = name
        self._filename = filename
        self._lineno = lineno
        self.props: dict[str, Property] = {}
        self.nodes: dict[str, Node] = {}
        self.labels: list[str] = []
        self.parent = parent
        self.dt = dt

        self._omit_if_no_ref = False
        self._is_referenced = False

        if name.count("@") > 1:
            dt._parse_error("multiple '@' in node name")
        if name != "/":
            for char in name:
                if char not in nodename_chars:
                    dt._parse_error(
                        f"{self.path}: bad character '{char}' in node name"
                    )

    @property
    def name(self) -> str:
        """
        See the class documentation.
        """
        # Converted to a property to discourage renaming -- that has to be done
        # via DT.move_node.
        name, sep, address = self._name.partition("@")

        if sep and address:  # means '@' was found
            return f"{name}@{address.lower()}"
        else:
            return name

    @property
    def lineno(self) -> int:
        """
        See the class documentation.
        """
        return self._lineno

    @property
    def filename(self) -> str:
        """
        See the class documentation.
        """
        return self._filename

    @property
    def unit_addr(self) -> str:
        """
        See the class documentation.
        """
        return self.name.partition("@")[2]

    @property
    def path(self) -> str:
        """
        See the class documentation.
        """
        node_names = []

        # This dynamic computation is required to be able to move
        # nodes in the DT class.
        cur = self
        while cur.parent:
            node_names.append(cur.name)
            cur = cur.parent

        return "/" + "/".join(reversed(node_names))

    def node_iter(self) -> Iterable["Node"]:
        """
        Returns a generator for iterating over the node and its children,
        recursively.

        For example, this will iterate over all nodes in the tree (like
        dt.node_iter()).

          for node in dt.root.node_iter():
              ...
        """
        yield self
        for node in self.nodes.values():
            yield from node.node_iter()

    def _get_prop(self, name: str) -> "Property":
        # Returns the property named 'name' on the node, creating it if it
        # doesn't already exist. Move the entry to the end of the props
        # dictionary so the order is preserved in the output DTS file.

        prop = self.props.pop(name, None)
        if not prop:
            prop = Property(self, name)
        self.props[name] = prop
        return prop

    def _del(self) -> None:
        # Removes the node from the tree. When called on the root node,
        # this method will leave it empty but still part of the tree.

        if self.parent is None:
            self.nodes.clear()
            self.props.clear()
            return
        self.parent.nodes.pop(self.name)  # type: ignore

    def __str__(self):
        """
        Returns a DTS representation of the node. Called automatically if the
        node is print()ed.
        """

        def safe_relpath(filename):
            # Returns a relative path to the file, or the absolute path if
            # a relative path cannot be established (on Windows with files
            # in different drives, for example).
            try:
                return os.path.relpath(filename, start=self.dt._base_dir)
            except ValueError:
                return filename

        rel_filename = safe_relpath(self.filename)
        s = (
            f"\n/* node '{self.path}' defined in"
            f" {rel_filename}:{self.lineno} */\n"
        )
        s += "".join(label + ": " for label in self.labels)

        s += f"{self.name} {{\n"

        lines = []
        comments = {}
        for prop in self.props.values():
            prop_str = textwrap.indent(str(prop), "\t")
            lines.extend(prop_str.splitlines(True))

            rel_filename = safe_relpath(prop.filename)
            comment = f"/* in {rel_filename}:{prop.lineno} */"
            comments[len(lines) - 1] = comment

        if lines:
            max_len = max([len(line.rstrip()) for line in lines])
            for i, line in enumerate(lines):
                drawn = line
                if i in comments:
                    drawn += (
                        " " * (max_len - len(line) + 1) + comments[i] + "\n"
                    )
                s += drawn

        for child in self.nodes.values():
            s += textwrap.indent(child.__str__(), "\t") + "\n"

        s += "};"

        return s

    def __repr__(self):
        """
        Returns some information about the Node instance. Called automatically
        if the Node instance is evaluated.
        """
        return f"<Node {self.path} in {self.filename}:{self.lineno}>"


# See Property.type
class Type(enum.IntEnum):
    EMPTY = 0
    BYTES = 1
    NUM = 2
    NUMS = 3
    STRING = 4
    STRINGS = 5
    PATH = 6
    PHANDLE = 7
    PHANDLES = 8
    PHANDLES_AND_NUMS = 9
    COMPOUND = 10


class MarkerType(enum.IntEnum):
    # Types of markers in property values

    # References
    PATH = 0  # &foo
    PHANDLE = 1  # <&foo>
    LABEL = 2  # foo: <1 2 3>

    # Start of data blocks of specific type
    UINT8 = 3  # [00 01 02] (and also used for /incbin/)
    UINT16 = 4  # /bits/ 16 <1 2 3>
    UINT32 = 5  # <1 2 3>
    UINT64 = 6  # /bits/ 64 <1 2 3>
    STRING = 7  # "foo"


class Property:
    """
    Represents a property ('x = ...').

    These attributes are available on Property instances:

    name:
      The name of the property (a string).

    filename:
      The name of the .dts file where the property is defined

    lineno:
      The line number in the .dts file where the property starts.

    value:
      The value of the property, as a 'bytes' string. Numbers are stored in
      big-endian format, and strings are null-terminated. Putting multiple
      comma-separated values in an assignment (e.g., 'x = < 1 >, "foo"') will
      concatenate the values.

      See the to_*() methods for converting the value to other types.

    type:
      The type of the property, inferred from the syntax used in the
      assignment. This is one of the following constants (with example
      assignments):

        Assignment                  | Property.type
        ----------------------------+------------------------
        foo;                        | dtlib.Type.EMPTY
        foo = [];                   | dtlib.Type.BYTES
        foo = [01 02];              | dtlib.Type.BYTES
        foo = /bits/ 8 <1>;         | dtlib.Type.BYTES
        foo = <1>;                  | dtlib.Type.NUM
        foo = <>;                   | dtlib.Type.NUMS
        foo = <1 2 3>;              | dtlib.Type.NUMS
        foo = <1 2>, <3>;           | dtlib.Type.NUMS
        foo = "foo";                | dtlib.Type.STRING
        foo = "foo", "bar";         | dtlib.Type.STRINGS
        foo = <&l>;                 | dtlib.Type.PHANDLE
        foo = <&l1 &l2 &l3>;        | dtlib.Type.PHANDLES
        foo = <&l1 &l2>, <&l3>;     | dtlib.Type.PHANDLES
        foo = <&l1 1 2 &l2 3 4>;    | dtlib.Type.PHANDLES_AND_NUMS
        foo = <&l1 1 2>, <&l2 3 4>; | dtlib.Type.PHANDLES_AND_NUMS
        foo = &l;                   | dtlib.Type.PATH
        *Anything else*             | dtlib.Type.COMPOUND

      *Anything else* includes properties mixing phandle (<&label>) and node
      path (&label) references with other data.

      Data labels in the property value do not influence the type.

    labels:
      A list with all labels pointing to the property, in the same order as the
      labels appear, but with duplicates removed.

      'label_1: label2: x = ...' gives 'labels' the value
      ["label_1", "label_2"].

    offset_labels:
      A dictionary that maps any labels within the property's value to their
      offset, in bytes. For example, 'x = < 0 label_1: 1 label_2: >' gives
      'offset_labels' the value {"label_1": 4, "label_2": 8}.

      Iteration order will match the order of the labels on Python versions
      that preserve dict insertion order.

    node:
      The Node the property is on.
    """

    #
    # Public interface
    #

    def __init__(self, node: Node, name: str):
        # Remember to update DT.__deepcopy__() if you change this.

        if "@" in name:
            node.dt._parse_error("'@' is only allowed in node names")

        self.name = name
        self.filename = ""
        self.lineno = -1
        self.value = b""
        self.labels: list[str] = []
        # We have to wait to set this until later, when we've got
        # the entire tree.
        self.offset_labels: dict[str, int] = {}
        self.node: Node = node

        self._label_offset_lst: list[tuple[str, int]] = []

        # A list of [offset, label, type] lists (sorted by offset),
        # giving the locations of references within the value. 'type'
        # is either MarkerType.PATH, for a node path reference,
        # MarkerType.PHANDLE, for a phandle reference, or
        # MarkerType.LABEL, for a label on/within data. Node paths
        # and phandles need to be patched in after parsing.
        self._markers: list[list] = []

        # Set of byte offsets where 32-bit cells were parsed from negative
        # literals (e.g. '(-1)'). Used by to_num/to_nums(signed_aware=True) to
        # distinguish intentional negative values from large unsigned ones.
        self._signed_cell_offsets: set[int] = set()

    @property
    def type(self) -> Type:  # noqa: PLR0911
        """
        See the class documentation.
        """
        # Data labels (e.g. 'foo = label: <3>') are irrelevant, so filter them
        # out
        types = [
            marker[1]
            for marker in self._markers
            if marker[1] != MarkerType.LABEL
        ]

        if not types:
            return Type.EMPTY

        if types == [MarkerType.UINT8]:
            return Type.BYTES

        if types == [MarkerType.UINT32]:
            return Type.NUM if len(self.value) == 4 else Type.NUMS

        # Treat 'foo = <1 2 3>, <4 5>, ...' as Type.NUMS too
        if set(types) == {MarkerType.UINT32}:
            return Type.NUMS

        if set(types) == {MarkerType.STRING}:
            return Type.STRING if len(types) == 1 else Type.STRINGS

        if types == [MarkerType.PATH]:
            return Type.PATH

        if (
            types == [MarkerType.UINT32, MarkerType.PHANDLE]
            and len(self.value) == 4
        ):
            return Type.PHANDLE

        if set(types) == {MarkerType.UINT32, MarkerType.PHANDLE}:
            if len(self.value) == 4 * types.count(MarkerType.PHANDLE):
                # Array with just phandles in it
                return Type.PHANDLES
            # Array with both phandles and numbers
            return Type.PHANDLES_AND_NUMS

        return Type.COMPOUND

    def to_num(self, signed=False, signed_aware=False) -> int:
        """
        Returns the value of the property as a number.

        Raises DTError if the property was not assigned with this syntax (has
        Property.type Type.NUM):

            foo = < 1 >;

        signed (default: False):
          If True, the value will be interpreted as signed rather than
          unsigned.

        signed_aware (default: False):
          If True, uses signed interpretation only for cells written as
          negative literals (e.g. '< (-1) >') in the DTS source. Positive
          literals and hex values remain unsigned. Takes precedence over
          'signed' when True.
        """
        if self.type is not Type.NUM:
            err(
                f"expected property '{self.name}' on {self.node.path} in "
                f"{self.filename}:{self.lineno} to be assigned with "
                f"'{self.name} = < (number) >;', not '{self}'"
            )

        if signed_aware:
            return int.from_bytes(
                self.value,
                "big",
                signed=0 in self._signed_cell_offsets,
            )

        return int.from_bytes(self.value, "big", signed=signed)

    def to_nums(self, signed=False, signed_aware=False) -> list[int]:
        """
        Returns the value of the property as a list of numbers.

        Raises DTError if the property was not assigned with this syntax (has
        Property.type Type.NUM or Type.NUMS):

            foo = < 1 2 ... >;

        signed (default: False):
          If True, the values will be interpreted as signed rather than
          unsigned.

        signed_aware (default: False):
          If True, uses signed interpretation only for cells written as
          negative literals (e.g. '< (-1) 2 3 >') in the DTS source. Positive
          literals and hex values remain unsigned. Takes precedence over
          'signed' when True.
        """
        if self.type not in (Type.NUM, Type.NUMS):
            err(
                f"expected property '{self.name}' on {self.node.path} in "
                f"{self.filename}:{self.lineno} to be assigned with "
                f"'{self.name} = < (number) (number) ... >;', not '{self}'"
            )

        if signed_aware:
            offsets = self._signed_cell_offsets
            return [
                int.from_bytes(
                    self.value[i : i + 4],
                    "big",
                    signed=i in offsets,
                )
                for i in range(0, len(self.value), 4)
            ]

        return [
            int.from_bytes(self.value[i : i + 4], "big", signed=signed)
            for i in range(0, len(self.value), 4)
        ]

    def to_bytes(self) -> bytes:
        """
        Returns the value of the property as a raw 'bytes', like
        Property.value, except with added type checking.

        Raises DTError if the property was not assigned with this syntax (has
        Property.type Type.BYTES):

            foo = [ 01 ... ];
        """
        if self.type is not Type.BYTES:
            err(
                f"expected property '{self.name}' on {self.node.path} "
                f"in {self.filename}:{self.lineno} to be assigned with "
                f"'{self.name} = [ (byte) (byte) ... ];', not '{self}'"
            )

        return self.value

    def to_string(self) -> str:
        """
        Returns the value of the property as a string.

        Raises DTError if the property was not assigned with this syntax (has
        Property.type Type.STRING):

            foo = "string";

        This function might also raise UnicodeDecodeError if the string is
        not valid UTF-8.
        """
        if self.type is not Type.STRING:
            err(
                f"expected property '{self.name}' on {self.node.path} "
                f"in {self.filename}:{self.lineno} to be assigned with "
                f"'{self.name} = \"string\";', not '{self}'"
            )

        try:
            ret = self.value.decode("utf-8")[:-1]  # Strip null
        except UnicodeDecodeError:
            err(
                f"value of property '{self.name}' ({self.value!r}) "
                f"on {self.node.path} in {self.filename}:{self.lineno} "
                "is not valid UTF-8"
            )

        return ret  # The separate 'return' appeases the type checker.

    def to_strings(self) -> list[str]:
        """
        Returns the value of the property as a list of strings.

        Raises DTError if the property was not assigned with this syntax (has
        Property.type Type.STRING or Type.STRINGS):

            foo = "string", "string", ... ;

        Also raises DTError if any of the strings are not valid UTF-8.
        """
        if self.type not in (Type.STRING, Type.STRINGS):
            err(
                f"expected property '{self.name}' on {self.node.path} in "
                f"{self.filename}:{self.lineno} to be assigned with "
                f"'{self.name} = \"string\", \"string\", ... ;', not '{self}'"
            )

        try:
            ret = self.value.decode("utf-8").split("\0")[:-1]
        except UnicodeDecodeError:
            err(
                f"value of property '{self.name}' ({self.value!r}) "
                f"on {self.node.path} in {self.filename}:{self.lineno} "
                "is not valid UTF-8"
            )

        return ret  # The separate 'return' appeases the type checker.

    def to_node(self) -> Node:
        """
        Returns the Node the phandle in the property points to.

        Raises DTError if the property was not assigned with this syntax (has
        Property.type Type.PHANDLE).

            foo = < &bar >;
        """
        if self.type is not Type.PHANDLE:
            err(
                f"expected property '{self.name}' on {self.node.path} in "
                f"{self.filename}:{self.lineno} to be assigned with "
                f"'{self.name} = < &foo >;', not '{self}'"
            )

        return self.node.dt.phandle2node[int.from_bytes(self.value, "big")]

    def to_nodes(self) -> list[Node]:
        """
        Returns a list with the Nodes the phandles in the property point to.

        Raises DTError if the property value contains anything other than
        phandles. All of the following are accepted:

            foo = < >
            foo = < &bar >;
            foo = < &bar &baz ... >;
            foo = < &bar ... >, < &baz ... >;
        """

        def type_ok():
            if self.type in (Type.PHANDLE, Type.PHANDLES):
                return True
            # Also accept 'foo = < >;'
            return self.type is Type.NUMS and not self.value

        if not type_ok():
            err(
                f"expected property '{self.name}' on {self.node.path} in "
                f"{self.filename}:{self.lineno} to be assigned with "
                f"'{self.name} = < &foo &bar ... >;', not '{self}'"
            )

        return [
            self.node.dt.phandle2node[
                int.from_bytes(self.value[i : i + 4], "big")
            ]
            for i in range(0, len(self.value), 4)
        ]

    def to_path(self) -> Node:
        """
        Returns the Node referenced by the path stored in the property.

        Raises DTError if the property was not assigned with either of these
        syntaxes (has Property.type Type.PATH or Type.STRING):

            foo = &bar;
            foo = "/bar";

        For the second case, DTError is raised if the path does not exist.
        """
        if self.type not in (Type.PATH, Type.STRING):
            err(
                f"expected property '{self.name}' on {self.node.path} in "
                f"{self.filename}:{self.lineno} to be assigned with either "
                f"'{self.name} = &foo' or '{self.name} = \"/path/to/node\"', "
                f"not '{self}'"
            )

        try:
            path = self.value.decode("utf-8")[:-1]
        except UnicodeDecodeError:
            err(
                f"value of property '{self.name}' ({self.value!r}) "
                f"on {self.node.path} in {self.filename}:{self.lineno} "
                "is not valid UTF-8"
            )

        try:
            ret = self.node.dt.get_node(path)
        except DTError:
            err(
                f"property '{self.name}' on {self.node.path} in "
                f"{self.filename}:{self.lineno} points to the non-existent "
                f'node "{path}"'
            )

        return ret  # The separate 'return' appeases the type checker.

    def __str__(self):  # noqa: PLR0912
        s = "".join(label + ": " for label in self.labels) + self.name
        if not self.value:
            return s + ";"

        s += " ="
        newline = "\n" + " " * len(s)

        for i, (marker_pos, marker_type, ref) in enumerate(self._markers):
            pos = marker_pos
            if i < len(self._markers) - 1:
                next_marker = self._markers[i + 1]
            else:
                next_marker = None

            # End of current marker
            end = next_marker[0] if next_marker else len(self.value)

            if marker_type is MarkerType.STRING:
                # end - 1 to strip off the null terminator
                s += f' "{_decode_and_escape(self.value[pos : end - 1])}"'
                if end != len(self.value):
                    s += f",{newline}"
            elif marker_type is MarkerType.PATH:
                s += " &" + ref
                if end != len(self.value):
                    s += f",{newline}"
            else:
                # <> or []

                if marker_type is MarkerType.LABEL:
                    s += f" {ref}:"
                elif marker_type is MarkerType.PHANDLE:
                    s += " &" + ref
                    pos += 4
                    if pos != len(self.value) and len(s) - array_start > 80:  # noqa: F821
                        s += array_newline  # noqa: F821
                        array_start = len(s)
                    # Subtle: There might be more data between the phandle and
                    # the next marker, so we can't 'continue' here
                else:  # marker_type is MarkerType.UINT*
                    elm_size = _TYPE_TO_N_BYTES[marker_type]
                    s += _N_BYTES_TO_START_STR[elm_size]
                    array_start = len(s)
                    array_newline = "\n" + " " * array_start

                while pos != end:
                    num = int.from_bytes(
                        self.value[pos : pos + elm_size], "big"
                    )
                    if elm_size == 1:
                        s += f" {num:02X}"
                    else:
                        s += f" {hex(num)}"

                    pos += elm_size
                    if pos != len(self.value) and len(s) - array_start > 80:
                        s += array_newline
                        array_start = len(s)

                if pos != 0 and (
                    not next_marker
                    or next_marker[1]
                    not in (MarkerType.PHANDLE, MarkerType.LABEL)
                ):
                    s += _N_BYTES_TO_END_STR[elm_size]
                    if pos != len(self.value):
                        s += f",{newline}"

        return s + ";"

    def __repr__(self):
        return (
            f"<Property '{self.name}' on {self.node.path} in"
            f" {self.filename}:{self.lineno}>"
        )

    #
    # Internal functions
    #

    def _add_marker(self, marker_type: MarkerType, data: Any = None):
        # Helper for registering markers in the value that are processed after
        # parsing. See _fixup_props(). 'marker_type' identifies the type of
        # marker, and 'data' has any optional data associated with the marker.

        # len(self.value) gives the current offset. This function is called
        # while the value is built. We use a list instead of a tuple to be able
        # to fix up offsets later (they might increase if the value includes
        # path references, e.g. 'foo = &bar, <3>;', which are expanded later).
        self._markers.append([len(self.value), marker_type, data])

        # For phandle references, add a dummy value with the same length as a
        # phandle. This is handy for the length check in _register_phandles().
        if marker_type is MarkerType.PHANDLE:
            self.value += b"\0\0\0\0"


#
# Public functions
#


def to_num(
    data: bytes,
    length: Optional[int] = None,
    signed: bool = False,
) -> int:
    """
    Converts the 'bytes' array 'data' to a number. The value is expected to be
    in big-endian format, which is standard in devicetree.

    length (default: None):
      The expected length of the value in bytes, as a simple type check. If
      None, the length check is skipped.

    signed (default: False):
      If True, the value will be interpreted as signed rather than unsigned.
    """
    _check_is_bytes(data)
    if length is not None:
        _check_length_positive(length)
        if len(data) != length:
            err(f"{data!r} is {len(data)} bytes long, expected {length}")

    return int.from_bytes(data, "big", signed=signed)


def to_nums(data: bytes, length: int = 4, signed: bool = False) -> list[int]:
    """
    Like Property.to_nums(), but takes an arbitrary 'bytes' array. The values
    are assumed to be in big-endian format, which is standard in devicetree.
    """
    _check_is_bytes(data)
    _check_length_positive(length)

    if len(data) % length:
        err(
            f"{data!r} is {len(data)} bytes long, "
            f"expected a length that's a multiple of {length}"
        )

    return [
        int.from_bytes(data[i : i + length], "big", signed=signed)
        for i in range(0, len(data), length)
    ]


#
# Private helpers
#


def err(msg) -> NoReturn:
    raise DTError(msg)


def _check_is_bytes(data):
    if not isinstance(data, bytes):
        err(f"'{data}' has type '{type(data).__name__}', expected 'bytes'")


def _check_length_positive(length):
    if length < 1:
        err("'length' must be greater than zero, was " + str(length))


def _decode_and_escape(b):
    # Decodes the 'bytes' array 'b' as UTF-8 and backslash-escapes special
    # characters

    # Hacky but robust way to avoid double-escaping any '\' spit out by
    # 'backslashreplace' bytes.translate() can't map to more than a single
    # byte, but str.translate() can map to more than one character, so it's
    # nice here. There's probably a nicer way to do this.
    return (
        b.decode("utf-8", "surrogateescape")
        .translate(_escape_table)
        .encode("utf-8", "surrogateescape")
        .decode("utf-8", "backslashreplace")
    )


_escape_table = str.maketrans(
    {
        "\\": "\\\\",
        '"': '\\"',
        "\a": "\\a",
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\v": "\\v",
        "\f": "\\f",
        "\r": "\\r",
    }
)


_TYPE_TO_N_BYTES = {
    MarkerType.UINT8: 1,
    MarkerType.UINT16: 2,
    MarkerType.UINT32: 4,
    MarkerType.UINT64: 8,
}

N_BYTES_TO_TYPE = {
    1: MarkerType.UINT8,
    2: MarkerType.UINT16,
    4: MarkerType.UINT32,
    8: MarkerType.UINT64,
}


_N_BYTES_TO_START_STR = {
    1: " [",
    2: " /bits/ 16 <",
    4: " <",
    8: " /bits/ 64 <",
}


_N_BYTES_TO_END_STR = {
    1: " ]",
    2: " >",
    4: " >",
    8: " >",
}
