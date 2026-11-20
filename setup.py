#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""Build hook generating configs, FFI definitions and native libraries."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

from setuptools import Distribution, setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent
NATIVE_DIR = ROOT / "pyremu" / "_native"
CONFIGS_PY = ROOT / "pyremu" / "configs_gen.py"
CONFIGS_RS = NATIVE_DIR / "cpu" / "src" / "configs_gen.rs"
DEFS_PY = NATIVE_DIR / "defs_gen.py"
LIB_NAMES = ("libdecode.so", "libtermio.so")

PURE_WHEEL = os.environ.get("PYREMU_PURE_WHEEL") == "1"
CARGO_OFFLINE = os.environ.get("PYREMU_CARGO_OFFLINE") == "1"


def _run(cmd: list[str], purpose: str) -> None:
    print(" ".join(cmd), flush=True)
    try:
        subprocess.run(cmd, cwd=ROOT, check=True)
    except FileNotFoundError:
        raise SystemExit(
            f"missing build tool {cmd[0]!r}: required to {purpose}; "
            "install make and the Rust toolchain (cargo)"
        ) from None
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"failed to {purpose}: {' '.join(cmd)} returned {exc.returncode}"
        ) from None


def _is_stale(target: Path, sources: list[Path]) -> bool:
    if not target.exists():
        return True

    return target.stat().st_mtime < max(
        (p.stat().st_mtime for p in sources if p.exists()), default=0.0
    )


def _rust_sources() -> list[Path]:
    return sorted(NATIVE_DIR.rglob("*.rs")) + [
        NATIVE_DIR / "Cargo.toml",
        NATIVE_DIR / "Cargo.lock",
        NATIVE_DIR / "cpu" / "Cargo.toml",
        NATIVE_DIR / "termio" / "Cargo.toml",
    ]


def _mk_sources() -> list[Path]:
    return sorted((ROOT / "mk").glob("*.mk")) + [
        ROOT / "makefile",
        ROOT / "pyremu" / "makefile",
        ROOT / "bsp" / "sittim" / "config.mk",
    ]


def _cargo_build_cmd() -> list[str]:
    cmd = [
        "cargo",
        "build",
        "--release",
        "--manifest-path",
        str(NATIVE_DIR / "Cargo.toml"),
        "--workspace",
    ]
    if CARGO_OFFLINE:
        cmd.append("--offline")
    return cmd


class PyremuBuildPy(build_py):
    def run(self) -> None:
        self._build_generated_sources()
        super().run()
        if PURE_WHEEL:
            self._drop_native_libs()

    def _build_generated_sources(self) -> None:
        mk_sources = _mk_sources()
        rust_sources = _rust_sources()
        if _is_stale(CONFIGS_PY, mk_sources):
            _run(["make", "__configs-gen"], "generate pyremu/configs_gen.py")
        if _is_stale(CONFIGS_RS, mk_sources):
            _run(
                ["make", str(CONFIGS_RS.relative_to(ROOT))],
                "generate Rust config constants",
            )
        if _is_stale(DEFS_PY, rust_sources + [CONFIGS_RS]):
            _run(
                [sys.executable, str(NATIVE_DIR / "defs_aux.py")],
                "generate pyremu/_native/defs_gen.py",
            )
        if PURE_WHEEL:
            return
        if any(
            _is_stale(NATIVE_DIR / name, rust_sources + [CONFIGS_RS])
            for name in LIB_NAMES
        ):
            _run(_cargo_build_cmd(), "build native libraries")
            for name in LIB_NAMES:
                shutil.copy2(
                    NATIVE_DIR / "target" / "release" / name, NATIVE_DIR
                )

    def _drop_native_libs(self) -> None:
        build_native = Path(self.build_lib) / "pyremu" / "_native"
        for name in LIB_NAMES:
            (build_native / name).unlink(missing_ok=True)


class PlatformDistribution(Distribution):
    def has_ext_modules(self) -> bool:
        return not PURE_WHEEL


class PlatformWheel(bdist_wheel):
    def finalize_options(self) -> None:
        super().finalize_options()
        self.root_is_pure = PURE_WHEEL

    def get_tag(self) -> tuple[str, str, str]:
        if PURE_WHEEL:
            return "py3", "none", "any"
        _, _, platform = super().get_tag()
        return "py3", "none", platform


setup(
    cmdclass={"build_py": PyremuBuildPy, "bdist_wheel": PlatformWheel},
    distclass=PlatformDistribution,
)
