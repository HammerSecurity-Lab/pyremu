# Copyright (c) 2019, Nordic Semiconductor
# SPDX-License-Identifier: BSD-3-Clause
#
# 本文件由 Zephyr Project 的 python-devicetree 包中的 dtlib.py 拆分而来,
# 并做了模块切分、标识符更名与静态检查所需的少量改写.
# 版权声明与许可条款见同目录下的 LICENSE.

"""设备树的词法分析 — 源文本到记号序列."""

import errno
import os
import sys

from pyremu.utils.dev_tree.parser.model import err
from pyremu.utils.dev_tree.parser.tokens import (
    byte_re,
    FileStackElt,
    LEXER_DEFAULT,
    LEXER_EXPECT_BYTE,
    LEXER_EXPECT_PROPNODENAME,
    misc_re,
    num_re,
    propnodename_re,
    Token,
    token_re,
    TokenId,
    unescape_re,
)


class LexerOps:
    """词法分析的实现, 供语法分析器继承."""

    def _check_token(self, val):
        if self._peek_token().val == val:
            self._next_token()
            return True
        return False

    def _peek_token(self):
        if not self._saved_token:
            self._saved_token = self._next_token()
        return self._saved_token

    def _next_token(self):  # noqa: PLR0912, PLR0915
        if self._saved_token:
            tmp = self._saved_token
            self._saved_token = None
            return tmp

        while True:
            tok_id = None

            match = token_re.match(self._file_contents, self._tok_end_i)
            if match:
                tok_id = match.lastindex
                if tok_id == TokenId.CHAR_LITERAL:
                    val = self._unescape(match.group(tok_id).encode("utf-8"))
                    if len(val) != 1:
                        self._parse_error("character literals must be length 1")
                    tok_val = ord(val)
                else:
                    tok_val = match.group(tok_id)

            elif self._lexer_state is LEXER_DEFAULT:
                match = num_re.match(self._file_contents, self._tok_end_i)
                if match:
                    tok_id = TokenId.NUM
                    num_s = match.group(1)
                    tok_val = int(
                        num_s,
                        16
                        if num_s.startswith(("0x", "0X"))
                        else 8
                        if num_s[0] == "0"
                        else 10,
                    )

            elif self._lexer_state is LEXER_EXPECT_PROPNODENAME:
                match = propnodename_re.match(
                    self._file_contents, self._tok_end_i
                )
                if match:
                    tok_id = TokenId.PROPNODENAME
                    tok_val = match.group(1)
                    self._lexer_state = LEXER_DEFAULT

            else:  # self._lexer_state is LEXER_EXPECT_BYTE
                match = byte_re.match(self._file_contents, self._tok_end_i)
                if match:
                    tok_id = TokenId.BYTE
                    tok_val = int(match.group(), 16)

            if not tok_id:
                match = misc_re.match(self._file_contents, self._tok_end_i)
                if match:
                    tok_id = TokenId.MISC
                    tok_val = match.group()
                else:
                    self._tok_i = self._tok_end_i
                    # Could get here due to a node/property naming appearing in
                    # an unexpected context as well as for bad characters in
                    # files. Generate a token for it so that the error can
                    # trickle up to some context where we can give a more
                    # helpful error message.
                    return Token(TokenId.BAD, "<unknown token>")

            self._tok_i = match.start()
            self._tok_end_i = match.end()

            if tok_id == TokenId.SKIP:
                self._lineno += tok_val.count("\n")
                continue

            # /include/ is handled in the lexer in the C tools as well, and can
            # appear anywhere
            if tok_id == TokenId.INCLUDE:
                # Can have newlines between /include/ and the filename
                self._lineno += tok_val.count("\n")
                # Do this manual extraction instead of doing it in the regex so
                # that we can properly count newlines
                filename = tok_val[tok_val.find('"') + 1 : -1]
                self._enter_file(filename)
                continue

            if tok_id == TokenId.LINE:
                # #line directive
                self._lineno = int(tok_val.split()[0]) - 1
                self.filename = tok_val[tok_val.find('"') + 1 : -1]
                continue

            if tok_id == TokenId.EOF:
                if self._filestack:
                    self._leave_file()
                    continue
                return Token(TokenId.EOF, "<EOF>")

            # State handling

            if tok_id in (
                TokenId.DEL_PROP,
                TokenId.DEL_NODE,
                TokenId.OMIT_IF_NO_REF,
            ) or tok_val in ("{", ";"):
                self._lexer_state = LEXER_EXPECT_PROPNODENAME

            elif tok_val == "[":
                self._lexer_state = LEXER_EXPECT_BYTE

            elif tok_id in (TokenId.MEMRESERVE, TokenId.BITS) or tok_val == "]":
                self._lexer_state = LEXER_DEFAULT

            return Token(tok_id, tok_val)

    def _expect_token(self, tok_val):
        # Raises an error if the next token does not have the string value
        # 'tok_val'. Returns the token.

        tok = self._next_token()
        if tok.val != tok_val:
            self._parse_error(f"expected '{tok_val}', not '{tok.val}'")

        return tok

    def _expect_num(self):
        # Raises an error if the next token is not a number. Returns the token.

        tok = self._next_token()
        if tok.id != TokenId.NUM:
            self._parse_error("expected number")
        return tok.val

    def _parse_error(self, s):
        # 'rfind()' returns -1 for the first line of the file too
        column = self._tok_i - self._file_contents.rfind(
            "\n", 0, self._tok_i + 1
        )
        err(
            f"{self.filename}:{self._lineno} (column {column}): "
            f"parse error: {s}"
        )

    def _enter_file(self, filename):
        # Enters the /include/d file 'filename', remembering the position in
        # the /include/ing file for later

        self._filestack.append(
            FileStackElt(
                self.filename,
                self._lineno,
                self._file_contents,
                self._tok_end_i,
            )
        )

        # Handle escapes in filenames, just for completeness
        filename = self._unescape(filename.encode("utf-8"))
        try:
            filename = filename.decode("utf-8")
        except UnicodeDecodeError:
            self._parse_error("filename is not valid UTF-8")

        with self._open(filename, encoding="utf-8") as f:
            try:
                self._file_contents = f.read()
            except OSError as e:
                self._parse_error(e)

        # Check for recursive /include/
        for i, parent in enumerate(self._filestack):
            if filename == parent[0]:
                self._parse_error(
                    "recursive /include/:\n"
                    + " ->\n".join(
                        [
                            f"{parent[0]}:{parent[1]}"
                            for parent in self._filestack[i:]
                        ]
                        + [filename]
                    )
                )

        self.filename = f.name
        self._lineno = 1
        self._tok_end_i = 0

    def _leave_file(self):
        # Leaves an /include/d file, returning to the file that /include/d it

        self.filename, self._lineno, self._file_contents, self._tok_end_i = (
            self._filestack.pop()
        )

    #
    # Misc.
    #

    def _unescape(self, b):
        # Replaces backslash escapes in the 'bytes' array 'b'.
        # We can't do this at the string level, because the result might
        # not be valid UTF-8 when octal/hex escapes are involved.

        def sub(match):  # noqa: PLR0911
            esc = match.group(1)
            if esc == b"a":
                return b"\a"
            if esc == b"b":
                return b"\b"
            if esc == b"t":
                return b"\t"
            if esc == b"n":
                return b"\n"
            if esc == b"v":
                return b"\v"
            if esc == b"f":
                return b"\f"
            if esc == b"r":
                return b"\r"

            if esc[0] in b"01234567":
                # Octal escape
                try:
                    return int(esc, 8).to_bytes(1, "big")
                except OverflowError:
                    self._parse_error("octal escape out of range (> 255)")

            if esc[0] == ord("x") and len(esc) > 1:
                # Hex escape
                return int(esc[1:], 16).to_bytes(1, "big")

            # Return <char> as-is for other \<char>
            return esc[0].to_bytes(1, "big")

        return unescape_re.sub(sub, b)

    def _open(self, filename, mode="r", **kwargs):
        # Wrapper around standard Python open(), accepting the same params.
        # But searches for a 'filename' file in the directory of the current
        # file and the include path.

        # The C tools support specifying stdin with '-' too
        if filename == "-":
            return sys.stdin.buffer if "b" in mode else sys.stdin

        # Try the directory of the current file first
        dirname = os.path.dirname(self.filename)
        try:
            return open(os.path.join(dirname, filename), mode, **kwargs)
        except OSError as e:
            if e.errno != errno.ENOENT:
                self._parse_error(e)

            # Try each directory from the include path
            for path in self._include_path:
                try:
                    return open(os.path.join(path, filename), mode, **kwargs)
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        self._parse_error(e)
                    continue

            self._parse_error(f"'{filename}' could not be found")
