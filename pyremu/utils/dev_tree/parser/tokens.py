# Copyright (c) 2019, Nordic Semiconductor
# SPDX-License-Identifier: BSD-3-Clause
#
# 本文件由 Zephyr Project 的 python-devicetree 包中的 dtlib.py 拆分而来,
# 并做了模块切分、标识符更名与静态检查所需的少量改写.
# 版权声明与许可条款见同目录下的 LICENSE.

"""设备树的词法单元 — 记号编号、记号结构与词法状态."""

import enum
import re
import string
from typing import NamedTuple, Union


class TokenId(enum.IntEnum):
    # Token IDs used by the DT lexer.

    # These values must be contiguous and start from 1.
    INCLUDE = 1
    LINE = 2
    STRING = 3
    DTS_V1 = 4
    PLUGIN = 5
    MEMRESERVE = 6
    BITS = 7
    DEL_PROP = 8
    DEL_NODE = 9
    OMIT_IF_NO_REF = 10
    LABEL = 11
    CHAR_LITERAL = 12
    REF = 13
    INCBIN = 14
    SKIP = 15
    EOF = 16

    # These values must be larger than the above contiguous range.
    NUM = 17
    PROPNODENAME = 18
    MISC = 19
    BYTE = 20
    BAD = 21


class FileStackElt(NamedTuple):
    # Used for maintaining the /include/ stack.

    filename: str
    lineno: int
    contents: str
    pos: int


_TokVal = Union[int, str]


class Token(NamedTuple):
    id: int
    val: _TokVal

    def __repr__(self):
        id_repr = TokenId(self.id).name
        return f"Token(id=TokenId.{id_repr}, val={repr(self.val)})"


# A leading \ is allowed property and node names, probably to allow weird node
# names that would clash with other stuff
propnodename_re = re.compile(r"\\?([a-zA-Z0-9,._+*#?@-]+)")

# Node names are more restrictive than property names.
nodename_chars = set(string.ascii_letters + string.digits + ",._+-@")


# Lexer states
LEXER_DEFAULT = 0
LEXER_EXPECT_PROPNODENAME = 1
LEXER_EXPECT_BYTE = 2


num_re = re.compile(r"(0[xX][0-9a-fA-F]+|[0-9]+)(?:ULL|UL|LL|U|L)?")


# Misc. tokens that are tried after a property/node name. This is important, as
# there's overlap with the allowed characters in names.
misc_re = re.compile(
    "|".join(
        re.escape(pat)
        for pat in (
            "==",
            "!=",
            "!",
            "=",
            ",",
            ";",
            "+",
            "-",
            "*",
            "/",
            "%",
            "~",
            "?",
            ":",
            "^",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            "<<",
            "<=",
            "<",
            ">>",
            ">=",
            ">",
            "||",
            "|",
            "&&",
            "&",
        )
    )
)


byte_re = re.compile(r"[0-9a-fA-F]{2}")


# Matches a backslash escape within a 'bytes' array. Captures the 'c' part of
# '\c', where c might be a single character or an octal/hex escape.
unescape_re = re.compile(rb"\\([0-7]{1,3}|x[0-9A-Fa-f]{1,2}|.)")


def init_tokens():
    # Builds a (<token 1>)|(<token 2>)|... regex and returns it. The
    # way this is constructed makes the token's value as an int appear
    # in match.lastindex after a match.

    # Each pattern must have exactly one capturing group, which can capture any
    # part of the pattern. This makes match.lastindex match the token type.
    # Token.val is based on the captured string.
    token_spec = {
        TokenId.INCLUDE: r'(/include/\s*"(?:[^\\"]|\\.)*")',
        # #line directive or GCC linemarker
        TokenId.LINE: r'^#(?:line)?[ \t]+([0-9]+[ \t]+"(?:[^\\"]|\\.)*")(?:[ \t]+[0-9]+){0,4}',
        TokenId.STRING: r'"((?:[^\\"]|\\.)*)"',
        TokenId.DTS_V1: r"(/dts-v1/)",
        TokenId.PLUGIN: r"(/plugin/)",
        TokenId.MEMRESERVE: r"(/memreserve/)",
        TokenId.BITS: r"(/bits/)",
        TokenId.DEL_PROP: r"(/delete-property/)",
        TokenId.DEL_NODE: r"(/delete-node/)",
        TokenId.OMIT_IF_NO_REF: r"(/omit-if-no-ref/)",
        TokenId.LABEL: r"([a-zA-Z_][a-zA-Z0-9_]*):",
        TokenId.CHAR_LITERAL: r"'((?:[^\\']|\\.)*)'",
        TokenId.REF: r"&([a-zA-Z_][a-zA-Z0-9_]*|{[a-zA-Z0-9,._+*#?@/-]*})",
        TokenId.INCBIN: r"(/incbin/)",
        # Whitespace, C comments, and C++ comments
        TokenId.SKIP: r"(\s+|(?:/\*(?:.|\n)*?\*/)|//.*$)",
        # Return a token for end-of-file so that the parsing code can
        # always assume that there are more tokens when looking
        # ahead. This simplifies things.
        TokenId.EOF: r"(\Z)",
    }

    # MULTILINE is needed for C++ comments and #line directives
    return re.compile(
        "|".join(token_spec[tok_id] for tok_id in range(1, TokenId.EOF + 1)),
        re.MULTILINE | re.ASCII,
    )


token_re = init_tokens()
