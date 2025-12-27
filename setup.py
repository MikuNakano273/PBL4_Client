# setup.py
import os
import shutil
from pathlib import Path

import pybind11
from pybind11.setup_helpers import Pybind11Extension, build_ext
from setuptools import setup

# === CONFIGURE THESE PATHS ===
VCPKG_ROOT = Path(r"C:/vcpkg")
YARA_DLL = VCPKG_ROOT / "packages/yara_x64-windows/bin/yara.dll"
OPENSSL_DLL_DIR = VCPKG_ROOT / "packages/openssl_x64-windows/bin"
SQLITE3_DLL = VCPKG_ROOT / "packages/sqlite3_x64-windows/bin/sqlite3.dll"


# === Pre-build validation helper ===
def validate_paths(paths, label, required=True):
    """
    Ensure each path in `paths` exists on disk.
    If required is True and any path is missing, raise RuntimeError to fail early with a clear message.
    If required is False, print warnings instead.
    """
    missing = [p for p in paths if not Path(p).exists()]
    if missing:
        msg = f"{label} missing or not found:\n" + "\n".join(str(p) for p in missing)
        if required:
            raise RuntimeError(msg)
        else:
            print("Warning: " + msg)


# We will define include_dirs and library_dirs variables and validate them before build
INCLUDE_DIRS = [
    r"C:/vcpkg/packages/yara_x64-windows/include",
    r"C:/vcpkg/packages/openssl_x64-windows/include",
    r"C:/vcpkg/packages/sqlite3_x64-windows/include",
]

# Ensure pybind11 headers are discoverable during build (insert at front if available)
try:
    pybind11_include = pybind11.get_include()
    if pybind11_include:
        INCLUDE_DIRS.insert(0, pybind11_include)
except Exception:
    # If we cannot query pybind11, continue — the validate_paths call will catch missing headers.
    pass

LIBRARY_DIRS = [
    r"C:/vcpkg/packages/yara_x64-windows/lib",
    r"C:/vcpkg/packages/openssl_x64-windows/lib",
    r"C:/vcpkg/packages/sqlite3_x64-windows/lib",
]

# Validate the key directories early so the developer sees a clear error before compilation starts.
# We treat include dirs and library dirs as required.
try:
    validate_paths(
        INCLUDE_DIRS,
        "Include directories (ensure dev headers are installed)",
        required=True,
    )
    validate_paths(
        LIBRARY_DIRS,
        "Library directories (ensure .lib files are installed)",
        required=True,
    )
except RuntimeError as e:
    # Surface friendly message and re-raise to stop the build early.
    print("\nDependency check failed before build:\n" + str(e) + "\n")
    raise


class CopyDLLsBuildExt(build_ext):
    def run(self):
        super().run()
        for ext in self.extensions:
            # copy DLLs for both extensions if those extensions were built
            if ext.name == "yarascanner" or ext.name == "quarantinemanager":
                self.copy_dlls(ext)

    def copy_dlls(self, ext):
        fullname = self.get_ext_fullpath(ext.name)
        target_dir = Path(fullname).parent

        # Copy yara.dll
        if YARA_DLL.exists():
            shutil.copy(YARA_DLL, target_dir)
            print(f"Copied {YARA_DLL.name} to {target_dir}")
        else:
            print(f"Warning: {YARA_DLL} not found!")

        # Copy OpenSSL DLLs
        if OPENSSL_DLL_DIR.exists():
            for dll in ["libcrypto-3-x64.dll", "libssl-3-x64.dll"]:
                src = OPENSSL_DLL_DIR / dll
                if src.exists():
                    shutil.copy(src, target_dir)
                    print(f"Copied {dll} to {target_dir}")
                else:
                    print(f"Warning: {dll} not found in {OPENSSL_DLL_DIR}")

        # Copy sqlite3.dll
        if SQLITE3_DLL.exists():
            shutil.copy(SQLITE3_DLL, target_dir)
            print(f"Copied {SQLITE3_DLL.name} to {target_dir}")
        else:
            print(f"Warning: {SQLITE3_DLL} not found!")


ext_modules = [
    Pybind11Extension(
        "yarascanner",
        [
            "cpp_extension/YaraScanner/bindings.cpp",
            "cpp_extension/YaraScanner/YaraScanner.cpp",
        ],
        include_dirs=INCLUDE_DIRS,
        libraries=[
            "libyara",
            "libcrypto",
            "libssl",
            "advapi32",
            "sqlite3",
            "crypt32",
            "wintrust",
        ],
        library_dirs=LIBRARY_DIRS,
        language="c++",
        cxx_std=17,  # ← CRITICAL: Enable C++17 for std::filesystem
    ),
    Pybind11Extension(
        "quarantinemanager",
        [
            "cpp_extension/QuarantineManager/bindings.cpp",
            "cpp_extension/QuarantineManager/QuarantineManager.cpp",
        ],
        include_dirs=INCLUDE_DIRS,
        libraries=[
            "libcrypto",
            "libssl",
            "sqlite3",
            "advapi32",
            "crypt32",
            "wintrust",
        ],
        library_dirs=LIBRARY_DIRS,
        language="c++",
        cxx_std=17,
    ),
]

setup(
    name="MyProject",
    version="0.1",
    ext_modules=ext_modules,
    cmdclass={"build_ext": CopyDLLsBuildExt},
    zip_safe=False,
    install_requires=["pyside6", "pybind11", "psutil", "requests", "pycryptodome"],
)
