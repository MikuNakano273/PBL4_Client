cmake_minimum_required(VERSION 3.15)
project(yarascanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# === Find Python & pybind11 ===
find_package(Python3 REQUIRED COMPONENTS Interpreter Development)
find_package(pybind11 CONFIG REQUIRED)

# === Find OpenSSL ===
find_package(OpenSSL REQUIRED)

# === Find SQLite3 ===
find_package(SQLite3 REQUIRED)

# === Locate YARA ===
# Optionally allow users to provide YARA_ROOT or YARA_INCLUDE_DIR / YARA_LIBRARY
if (NOT DEFINED YARA_ROOT)
    set(YARA_ROOT "" CACHE PATH "Root directory of YARA installation (optional)")
endif()

if (NOT TARGET yara AND NOT DEFINED YARA_INCLUDE_DIR)
    if (YARA_ROOT)
        find_path(YARA_INCLUDE_DIR yara.h PATHS "${YARA_ROOT}/include" "${YARA_ROOT}/include/yara" NO_DEFAULT_PATH)
        find_library(YARA_LIBRARY NAMES yara libyara PATHS "${YARA_ROOT}/lib" NO_DEFAULT_PATH)
    endif()
    if (NOT YARA_INCLUDE_DIR)
        find_path(YARA_INCLUDE_DIR yara.h)
    endif()
    if (NOT YARA_LIBRARY)
        find_library(YARA_LIBRARY NAMES yara libyara)
    endif()
endif()

if (YARA_INCLUDE_DIR)
    message(STATUS "Found YARA include: ${YARA_INCLUDE_DIR}")
else()
    message(WARNING "YARA include not found. Set YARA_ROOT or YARA_INCLUDE_DIR if you need to build with YARA.")
endif()

if (YARA_LIBRARY)
    message(STATUS "Found YARA library: ${YARA_LIBRARY}")
else()
    message(WARNING "YARA library not found. Set YARA_ROOT or YARA_LIBRARY if needed.")
endif()

# === Source files for the yarascanner extension ===
set(SOURCES
    YaraScanner.cpp
    bindings.cpp
)

# === Build Python extension with pybind11 ===
pybind11_add_module(yarascanner ${SOURCES})

# Include directories: this source dir first
target_include_directories(yarascanner PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# If FindSQLite3 provided include dirs variable, use it
if (DEFINED SQLITE3_INCLUDE_DIRS)
    target_include_directories(yarascanner PRIVATE ${SQLITE3_INCLUDE_DIRS})
else()
    if (DEFINED SQLITE3_INCLUDE_DIR)
        target_include_directories(yarascanner PRIVATE ${SQLITE3_INCLUDE_DIR})
    endif()
endif()

# Add YARA include directory if found
if (YARA_INCLUDE_DIR)
    target_include_directories(yarascanner PRIVATE ${YARA_INCLUDE_DIR})
endif()

# Link libraries:
# - OpenSSL (imported targets)
# - SQLite3 (from find_package)
# - YARA library if found
target_link_libraries(yarascanner PRIVATE
    OpenSSL::Crypto
    OpenSSL::SSL
)

if (DEFINED SQLITE3_LIBRARIES)
    target_link_libraries(yarascanner PRIVATE ${SQLITE3_LIBRARIES})
elseif (SQLITE3_LIBRARY)
    target_link_libraries(yarascanner PRIVATE ${SQLITE3_LIBRARY})
else()
    message(WARNING "SQLite3 library not found via find_package. Ensure SQLite3 is available on the link path.")
endif()

if (YARA_LIBRARY)
    target_link_libraries(yarascanner PRIVATE ${YARA_LIBRARY})
else()
    message(STATUS "Building yarascanner without linking a YARA library. Provide YARA_LIBRARY or YARA_ROOT to link it.")
endif()

# Windows additional system libs
if (WIN32)
    target_link_libraries(yarascanner PRIVATE advapi32 crypt32 wintrust)
endif()

# Allow user to override VCPKG_ROOT from the cache
if (DEFINED VCPKG_ROOT)
    message(STATUS "VCPKG_ROOT is set: ${VCPKG_ROOT}")
endif()

# Helpful summary
message(STATUS "yarascanner configuration summary:")
message(STATUS "  CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(STATUS "  OpenSSL include dirs: ${OPENSSL_INCLUDE_DIR}")
if (DEFINED SQLITE3_INCLUDE_DIRS)
    message(STATUS "  SQLite3 include dirs: ${SQLITE3_INCLUDE_DIRS}")
elseif (DEFINED SQLITE3_INCLUDE_DIR)
    message(STATUS "  SQLite3 include dir: ${SQLITE3_INCLUDE_DIR}")
endif()
if (YARA_INCLUDE_DIR)
    message(STATUS "  YARA include: ${YARA_INCLUDE_DIR}")
endif()
if (YARA_LIBRARY)
    message(STATUS "  YARA lib: ${YARA_LIBRARY}")
endif()
