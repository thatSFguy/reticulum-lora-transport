# scripts/inject_fw_version.py
#
# PlatformIO pre-build extra script. Injects FW_VERSION as a quoted
# string macro so src/ConfigProtocol.cpp's ping handler reports the
# real build identity instead of a hardcoded literal that drifts
# every release.
#
# Resolution order:
#   1. GITHUB_REF=refs/tags/vX.Y.Z   → "vX.Y.Z"     (CI tag builds)
#   2. `git describe --tags --always --dirty`        (CI master / local dev)
#   3. "dev"                                          (no git, no env)

import os
import subprocess

Import("env")  # noqa: F821 — provided by SCons / PlatformIO


def _resolve_version() -> str:
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/"):
        return ref[len("refs/tags/"):]
    try:
        out = subprocess.check_output(
            ["git", "describe", "--tags", "--always", "--dirty"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        if out:
            return out
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return "dev"


version = _resolve_version()
# StringifyMacro wraps in quotes + escapes for use as a -D flag value.
env.Append(CPPDEFINES=[("FW_VERSION", env.StringifyMacro(version))])  # noqa: F821
print(f"inject_fw_version: FW_VERSION = {version}")
