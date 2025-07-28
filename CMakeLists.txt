cmake_minimum_required(VERSION 3.14)
project(NIDS LANGUAGES CXX)

# Set C++ standard and compiler options
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Project version
set(NIDS_VERSION_MAJOR 1)
set(NIDS_VERSION_MINOR 0)
set(NIDS_VERSION_PATCH 0)
set(NIDS_VERSION "${NIDS_VERSION_MAJOR}.${NIDS_VERSION_MINOR}.${NIDS_VERSION_PATCH}")

# Configuration options
option(BUILD_TESTS "Build tests" ON)
option(USE_BOOST "Use Boost regex" OFF)
option(GENERATE_DOCS "Generate documentation" OFF)

# Find required dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(PC_LIBPCAP REQUIRED libpcap)

# Include directories
include_directories(
    ${PC_LIBPCAP_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Source files
file(GLOB_RECURSE SOURCES 
    "src/*.cpp"
    "src/parsing/*.cpp"
    "src/rules/*.cpp"
)

# Executable target
add_executable(nids
    ${SOURCES}
    src/main.cpp
)

# Link libraries
target_link_libraries(nids PRIVATE ${PC_LIBPCAP_LIBRARIES})

# Optional Boost support
if(USE_BOOST)
    find_package(Boost 1.70.0 COMPONENTS regex REQUIRED)
    target_include_directories(nids PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(nids PRIVATE Boost::regex)
    target_compile_definitions(nids PRIVATE USE_BOOST_REGEX)
endif()

# Documentation
if(GENERATE_DOCS)
    find_package(Doxygen REQUIRED)
    set(DOXYGEN_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/docs)
    set(DOXYGEN_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
    doxygen_add_docs(docs ${DOXYGEN_SOURCE_DIR})
endif()

# Testing
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Installation
install(TARGETS nids DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)
install(DIRECTORY rules/ DESTINATION share/nids/rules)

# Package information
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/NIDSConfigVersion.cmake
    VERSION ${NIDS_VERSION}
    COMPATIBILITY AnyNewerVersion
)

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(nids PRIVATE -Wall -Wextra -pedantic)
endif()