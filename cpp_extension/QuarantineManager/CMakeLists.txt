cmake_minimum_required(VERSION 3.15)
project(quarantinemanager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# === Find Python & pybind11 ===
find_package(Python3 REQUIRED COMPONENTS Interpreter Development)
find_package(pybind11 CONFIG REQUIRED)

# === Find OpenSSL ===
find_package(OpenSSL REQUIRED)

# === Find SQLite3 ===
find_package(SQLite3 REQUIRED)

# === Source files ===
set(SOURCES
    QuarantineManager.cpp
    bindings.cpp
)

# === Build Python extension with pybind11 ===
pybind11_add_module(quarantinemanager ${SOURCES})

# Include directories for this target (expose current source dir to find header)
target_include_directories(quarantinemanager PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Include SQLite3 includes if available
if (DEFINED SQLITE3_INCLUDE_DIRS)
    target_include_directories(quarantinemanager PRIVATE ${SQLITE3_INCLUDE_DIRS})
else()
    if (DEFINED SQLITE3_INCLUDE_DIR)
        target_include_directories(quarantinemanager PRIVATE ${SQLITE3_INCLUDE_DIR})
    endif()
endif()

# Link libraries:
# - OpenSSL::Crypto and OpenSSL::SSL (modern CMake imported targets)
target_link_libraries(quarantinemanager PRIVATE
    OpenSSL::Crypto
    OpenSSL::SSL
)

# Link SQLite3
if (DEFINED SQLITE3_LIBRARIES)
    target_link_libraries(quarantinemanager PRIVATE ${SQLITE3_LIBRARIES})
elseif (SQLITE3_LIBRARY)
    target_link_libraries(quarantinemanager PRIVATE ${SQLITE3_LIBRARY})
else()
    message(WARNING "SQLite3 library not found via find_package. Ensure SQLite3 is available on the link path.")
endif()

# Windows additional system libs
if (WIN32)
    target_link_libraries(quarantinemanager PRIVATE advapi32 crypt32 wintrust)
endif()

# Provide helpful summary at configure time
message(STATUS "Configuration for quarantinemanager extension:")
message(STATUS "  CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(STATUS "  OpenSSL include dirs: ${OPENSSL_INCLUDE_DIR}")
if (DEFINED SQLITE3_INCLUDE_DIRS)
    message(STATUS "  SQLite3 include dirs: ${SQLITE3_INCLUDE_DIRS}")
elseif (DEFINED SQLITE3_INCLUDE_DIR)
    message(STATUS "  SQLite3 include dir: ${SQLITE3_INCLUDE_DIR}")
endif()
