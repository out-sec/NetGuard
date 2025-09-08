cmake_minimum_required(VERSION 3.10)
project(nids)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Header location
include_directories(include)

#configure_file("${CMAKE_SOURCE_DIR}/config/interface.cfg" 
#               "${CMAKE_BINARY_DIR}/config/interface.cfg" COPYONLY)

# Source files
set(SOURCES
    src/main.cpp
    src/entry.cpp
    src/parsers/http.cpp
    src/parsers/ethernet.cpp
    src/parsers/ipv4.cpp
    src/parsers/http.cpp
    src/rules/rules.cpp
    src/utils/decEthernet.cpp
    # src/utils/hex.cpp
    src/utils/decHttp.cpp
    src/config/interface.cpp
    src/utils/decIPv4.cpp
    src/parsers/arp.cpp
    src/parsers/tcp.cpp
    src/parsers/ftp.cpp
)

# Compiler warnings
add_compile_options(-Wall -Wextra -Wunused -Wunused-function -Wunused-variable)

# Optional: Dead code elimination
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
add_compile_options(-ffunction-sections -fdata-sections)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")

# Output
add_executable(nids ${SOURCES})
