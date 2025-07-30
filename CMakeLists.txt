cmake_minimum_required(VERSION 3.10)
project(nids)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/main.cpp
    src/parsers/ethernet.cpp
    src/utils/decEthernet.cpp
    src/config/interface.cpp
    src/parsers/ipv4.cpp
)

# Add executable
add_executable(nids ${SOURCES})
