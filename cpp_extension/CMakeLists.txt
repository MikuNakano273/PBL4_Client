cmake_minimum_required(VERSION 3.15)
project(pbl4_cpp_extensions LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Top-level orchestrator for multiple pybind11 extensions:
# - yarascanner (YARA-based scanner)
# - quarantinemanager (QuarantineManager implementation exposed as quarantinemanager)

# Optionally allow users to pass VCPKG_ROOT or YARA_ROOT from the command-line
if (NOT DEFINED VCPKG_ROOT)
    set(VCPKG_ROOT "" CACHE PATH "Optional vcpkg root (used by subprojects)")
endif()

if (NOT DEFINED YARA_ROOT)
    set(YARA_ROOT "" CACHE PATH "Optional YARA root (used by yarascanner subproject)")
endif()

message(STATUS "Configuring cpp_extension top-level. VCPKG_ROOT='${VCPKG_ROOT}', YARA_ROOT='${YARA_ROOT}'")

# Add subdirectories for each extension project. Each subdir contains its own CMakeLists
# and will create a separate Python extension (.pyd/.so) via pybind11_add_module.
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/YaraScanner)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/QuarantineManager)

message(STATUS "Subprojects added: YaraScanner, QuarantineManager")
