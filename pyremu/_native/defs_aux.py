#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""由 Rust 侧 LLVM IR 的调试元数据生成 FFI 定义.

流程分两步, 路径均以本文件所在目录为基准:

1. 对 cpu 与 termio 两个 crate 执行 ``cargo rustc --emit=llvm-ir``,
   带 ``-C debuginfo=2`` 取得含 DI 元数据的 IR;
2. 解析 IR, 写出 ``ffi_spec.json``, 再按其中的字段与函数签名生成
   ``defs_gen.py``.

llvmlite 的绑定层只解析 IR 的结构, 不提供读取调试元数据的入口
``add_debug_info`` 属于 ``llvmlite.ir`` 的构造侧接口; 结构体在 IR 中又是
匿名字面量类型, 字段名只能取自 DI 元数据, 故第 2 步解析文本形式的 IR.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import tempfile

NATIVE_DIR = Path(__file__).resolve().parent

SPEC_PATH = NATIVE_DIR / "ffi_spec.json"
DEFS_PATH = NATIVE_DIR / "defs_gen.py"

# 库名到 cargo 包名与 crate 根命名空间的映射.
# crate 根命名空间用于区分本 crate 的结构体与内联进来的 std 类型.
CRATES: dict[str, tuple[str, str]] = {
    "cpu": ("pyremu-native", "decode"),
    "termio": ("pyremu-termio", "termio"),
}

# 标量类型到 ctypes 的映射.
CTYPES_SCALARS: dict[str, str] = {
    "u8": "ctypes.c_uint8",
    "u16": "ctypes.c_uint16",
    "u32": "ctypes.c_uint32",
    "u64": "ctypes.c_uint64",
    "i32": "ctypes.c_int32",
    "bool": "ctypes.c_bool",
}

NODE_RE = re.compile(r"^!(\d+) = (?:distinct )?(.*)$")
PARAM_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*): "
    r'("(?:[^"\\]|\\.)*"|!\{[^}]*\}|![0-9]+|null|[^,)]+)'
)
DEFINE_RE = re.compile(
    r"^define [^@\n]*@([A-Za-z_][A-Za-z0-9_]*)\(", re.MULTILINE
)
# core::sync::atomic 的包装类型, 按其中的标量类型参与 ctypes 布局.
ATOMIC_RE = re.compile(r"^Atomic<(\w+)>$")


class Node:
    """DI 元数据的一个节点."""

    def __init__(self, tag: str, params: dict[str, str], body: str) -> None:
        self.tag = tag
        self.params = params
        self.body = body


def unquote(raw: str) -> str:
    """去掉 LLVM 字符串字面量的引号并处理转义."""
    if not raw.startswith('"'):
        return raw
    text = raw[1:-1]
    out = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            out.extend(char.encode("utf-8"))
            index += 1
            continue
        code = text[index + 1]
        if code == "n":
            out.extend(b"\n")
        elif code == "t":
            out.extend(b"\t")
        elif code in ('"', "\\"):
            out.extend(code.encode("utf-8"))
        else:
            out.append(int(text[index + 1 : index + 3], 16))
            index += 1
        index += 2
    return out.decode("utf-8")


def parse_nodes(ir_text: str) -> dict[str, Node]:
    """把 IR 末尾的元数据定义解析为节点表."""
    nodes: dict[str, Node] = {}
    for line in ir_text.splitlines():
        match = NODE_RE.match(line)
        if match is None:
            continue
        body = match.group(2)
        nodes[f"!{match.group(1)}"] = Node(
            body.split("(", 1)[0], dict(PARAM_RE.findall(body)), body
        )
    return nodes


def node_name(node: Node) -> str:
    """取节点的名字, 缺失时为空串."""
    return unquote(node.params.get("name", '""'))


def list_refs(node: Node) -> list[str]:
    """取 ``!{...}`` 列表节点内的引用, 保持原有顺序."""
    return re.findall(r"!\d+|null", node.body)


def type_token(ref: str, nodes: dict[str, Node]) -> str:
    """把一处 DI 类型引用翻译为字段类型写法."""
    if ref == "null":
        return "()"
    node = nodes[ref]
    if node.tag == "!DIBasicType":
        return unquote(node.params["name"])
    if node.tag == "!DIDerivedType":
        if node.params.get("tag") == "DW_TAG_pointer_type":
            return "ptr"
        return type_token(node.params["baseType"], nodes)
    if node.tag == "!DICompositeType":
        if node.params.get("tag") == "DW_TAG_array_type":
            element = type_token(node.params["baseType"], nodes)
            count = subrange_count(node.params["elements"], nodes)
            return f"[{element}; {count}]"
        name = unquote(node.params["name"])
        atomic = ATOMIC_RE.match(name)
        return atomic.group(1) if atomic else name
    raise ValueError(f"不支持的 DI 类型节点: {node.body[:120]}")


def subrange_count(ref: str, nodes: dict[str, Node]) -> int:
    """取数组类型的元素个数."""
    for sub_ref in list_refs(nodes[ref]):
        node = nodes[sub_ref]
        if node.tag == "!DISubrange":
            return int(node.params["count"])
    raise ValueError(f"数组类型缺少 DISubrange: {ref}")


def struct_of(
    ref: str,
    nodes: dict[str, Node],
) -> tuple[str, int, list[tuple[str, str]]] | None:
    """解析一个结构体节点, 非结构体返回 None."""
    node = nodes[ref]
    if node.tag != "!DICompositeType":
        return None
    if node.params.get("tag") != "DW_TAG_structure_type":
        return None
    name = unquote(node.params["name"])
    size = int(node.params["size"]) // 8
    fields = []
    for element_ref in list_refs(nodes[node.params["elements"]]):
        element = nodes[element_ref]
        if element.params.get("tag") != "DW_TAG_member":
            continue
        fields.append(
            (
                unquote(element.params["name"]),
                type_token(element.params["baseType"], nodes),
            )
        )
    return name, size, fields


def find_functions(
    ir_text: str,
    nodes: dict[str, Node],
) -> tuple[list[dict], list[str]]:
    """取 IR 中未改名的 define 符号对应的导出函数签名.

    返回值第二项是各函数返回类型与参数类型的 DI 引用, 供结构体收集使用.
    """
    names = {
        match.group(1)
        for match in DEFINE_RE.finditer(ir_text)
        if not match.group(1).startswith(("_R", "_ZN", "_"))
    }
    by_name: dict[str, list[Node]] = {}
    for node in nodes.values():
        if node.tag != "!DISubprogram":
            continue
        by_name.setdefault(node_name(node), []).append(node)
    functions = []
    roots: list[str] = []
    skipped = []
    for name in sorted(names):
        found = [
            node
            for node in by_name.get(name, [])
            if "DISPFlagDefinition" in node.params.get("spFlags", "")
            and unquote(node.params.get("linkageName", '""')) in ("", name)
        ]
        if not found:
            skipped.append(name)
            continue
        subroutine = nodes[found[0].params["type"]]
        types = list_refs(nodes[subroutine.params["types"]])
        if not types:
            skipped.append(name)
            continue
        functions.append(
            {
                "name": name,
                "ret": type_token(types[0], nodes),
                "args": [type_token(ref, nodes) for ref in types[1:]],
            }
        )
        roots.extend(types)
    if skipped:
        print(f"跳过缺少 DI 签名的符号: {', '.join(skipped)}")
    return functions, roots


def struct_names(token: str) -> list[str]:
    """取类型写法中出现的结构体名."""
    if token.startswith("[") and token.endswith("]"):
        return struct_names(token[1:-1].rpartition(";")[0].strip())
    if token in CTYPES_SCALARS or token in ("ptr", "()"):
        return []
    return [token]


def scope_root_name(ref: str, nodes: dict[str, Node]) -> str:
    """取结构体所在命名空间链最外层的名字."""
    node = nodes[ref]
    ref = node.params.get("scope", "")
    name = ""
    while ref in nodes:
        node = nodes[ref]
        if node.tag == "!DINamespace":
            name = node_name(node)
        ref = node.params.get("scope", "")
    return name


def referenced_structs(
    roots: list[str],
    nodes: dict[str, Node],
    crate_root: str,
) -> dict[str, tuple[int, list[tuple[str, str]]]]:
    """收集函数签名直接或间接引用的结构体.

    指针指向的结构体只在属于本 crate 时收录: 其余指针一律按裸地址传递,
    内联进来的 std 类型不需要 ctypes 定义.
    """
    index: dict[str, str] = {}
    for ref, node in nodes.items():
        if node.tag != "!DICompositeType":
            continue
        if node.params.get("tag") != "DW_TAG_structure_type":
            continue
        index.setdefault(node_name(node), ref)
    seen: dict[str, tuple[int, list[tuple[str, str]]]] = {}
    visited: set[str] = set()

    def visit_pointee(ref: str) -> None:
        if ref not in nodes:
            return
        target = nodes[ref]
        if target.tag != "!DICompositeType":
            return
        if target.params.get("tag") != "DW_TAG_structure_type":
            return
        if scope_root_name(ref, nodes) == crate_root:
            visit(ref)

    def visit_derived(node: Node) -> None:
        if node.params.get("tag") == "DW_TAG_pointer_type":
            visit_pointee(node.params.get("baseType", ""))
        else:
            visit(node.params.get("baseType", ""))

    def visit_composite(ref: str, node: Node) -> None:
        if node.params.get("tag") == "DW_TAG_array_type":
            visit(node.params.get("baseType", ""))
            return
        if scope_root_name(ref, nodes) != crate_root:
            return
        parsed = struct_of(ref, nodes)
        if parsed is None:
            return
        name, size, fields = parsed
        seen[name] = (size, fields)
        for element_ref in list_refs(nodes[node.params["elements"]]):
            element = nodes[element_ref]
            if element.params.get("tag") == "DW_TAG_member":
                visit(element.params["baseType"])

    def visit(ref: str) -> None:
        if ref in visited or ref not in nodes:
            return
        visited.add(ref)
        node = nodes[ref]
        if node.tag == "!DIDerivedType":
            visit_derived(node)
        elif node.tag == "!DICompositeType":
            visit_composite(ref, node)

    for ref in roots:
        visit(ref)
    return seen


def collect_library(
    lib_name: str,
) -> tuple[list[dict], dict[str, tuple[int, list[tuple[str, str]]]]]:
    """为一个 crate 生成 IR 并提取函数与结构体."""
    package, crate_root = CRATES[lib_name]
    with tempfile.TemporaryDirectory(prefix="pyremu-ir-") as tmp:
        ir_path = Path(tmp) / f"{lib_name}.ll"
        subprocess.run(
            [
                "cargo",
                "rustc",
                "-p",
                package,
                "--release",
                "--",
                f"--emit=llvm-ir={ir_path}",
                "-C",
                "debuginfo=2",
            ],
            cwd=NATIVE_DIR,
            check=True,
        )
        ir_text = ir_path.read_text(encoding="utf-8")
    nodes = parse_nodes(ir_text)
    functions, roots = find_functions(ir_text, nodes)
    return functions, referenced_structs(roots, nodes, crate_root)


def collect_all() -> tuple[dict, dict[str, list[dict]]]:
    """汇总两个库的函数与结构体声明."""
    structs: dict[str, tuple[int, list[tuple[str, str]]]] = {}
    functions: dict[str, list[dict]] = {}
    for lib_name in CRATES:
        lib_functions, lib_structs = collect_library(lib_name)
        functions[lib_name] = lib_functions
        for name, value in lib_structs.items():
            known = structs.get(name)
            if known is not None and known != value:
                raise ValueError(f"结构体 {name} 在两个库中定义不同")
            structs[name] = value
    return structs, functions


def topological(
    structs: dict[str, tuple[int, list[tuple[str, str]]]],
) -> list[str]:
    """按依赖顺序排列结构体, 被引用者在前."""
    order: list[str] = []

    def visit(name: str, stack: set[str]) -> None:
        if name in order:
            return
        if name in stack:
            raise ValueError(f"结构体定义成环: {name}")
        stack.add(name)
        for _, field_type in structs[name][1]:
            for dep in struct_names(field_type):
                visit(dep, stack)
        stack.discard(name)
        order.append(name)

    for name in sorted(structs):
        visit(name, set())
    return order


def ctype_expression(token: str) -> str:
    """把字段类型写法翻译为 ctypes 表达式."""
    if token == "()":
        return "None"
    if token == "ptr":
        return "ctypes.c_void_p"
    if token.startswith("[") and token.endswith("]"):
        element, _, count = token[1:-1].rpartition(";")
        return f"{ctype_expression(element.strip())} * {count.strip()}"
    return CTYPES_SCALARS.get(token, token)


def render(spec: dict) -> str:
    """渲染 defs_gen.py 的源码."""
    structs = spec["structs"]
    lines = [
        f"# generated from _native/ffi_spec.json by {Path(__file__).name}"
        + " — do not edit",
        '"""FFI 结构体与导出函数签名, 由 Rust 侧 LLVM IR 的 DI 元数据生成."""',
        "",
        "from __future__ import annotations",
        "",
        "import ctypes",
    ]
    for name, entry in structs.items():
        lines.append("")
        lines.append("")
        lines.append(f"class {name}(ctypes.Structure):")
        lines.append("    _fields_ = [")
        lines.extend(
            f'        ("{field}", {ctype_expression(token)}),'
            for field, token in entry["fields"]
        )
        lines.append("    ]")
    lines.append("")
    lines.append("")
    lines.append("STRUCTS = {")
    lines.extend(f'    "{name}": {name},' for name in structs)
    lines.append("}")
    lines.append("")
    lines.append("")
    lines.append("# 各结构体的字节数, 取自 Rust 侧 DI 元数据.")
    lines.append("STRUCT_SIZES = {")
    lines.extend(
        f'    "{name}": {entry["size"]},' for name, entry in structs.items()
    )
    lines.append("}")
    lines.append("")
    lines.append("")
    lines.append("# 库名到 (函数名, 返回类型, 参数类型) 列表的映射.")
    lines.append("FUNCTIONS = {")
    for lib_name, entries in spec["functions"].items():
        lines.append(f'    "{lib_name}": [')
        lines.extend(
            f'        ("{entry["name"]}", '
            f"{ctype_expression(entry['ret'])}, "
            f"[{', '.join(ctype_expression(arg) for arg in entry['args'])}]),"
            for entry in entries
        )
        lines.append("    ],")
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_if_changed(path: Path, text: str) -> None:
    """内容变化时写文件."""
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return
    path.write_text(text, encoding="utf-8")
    print(f"refresh {path.name}")


def main() -> None:
    """生成声明文件与 ctypes 定义模块."""
    structs, functions = collect_all()
    spec = {
        "structs": {
            name: {"size": structs[name][0], "fields": structs[name][1]}
            for name in topological(structs)
        },
        "functions": functions,
    }
    write_if_changed(
        SPEC_PATH, json.dumps(spec, ensure_ascii=False, indent=2) + "\n"
    )
    write_if_changed(DEFS_PATH, render(spec))
    print(
        f"{len(structs)} structs, "
        f"{sum(len(entries) for entries in functions.values())} functions"
    )


if __name__ == "__main__":
    main()
