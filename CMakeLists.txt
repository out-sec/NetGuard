cmake_minimum_required(VERSION 3.10)
project(NetGuard)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(
    ${PCAP_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
    include_directories(${CMAKE_SOURCE_DIR}/src)
)

add_executable(nids
    src/config/interface.cpp
    src/entry.cpp
    src/main.cpp
    src/parsers/arp.cpp
    src/parsers/ethernet.cpp
    src/parsers/ipv4.cpp
    src/parsing/http_parser.cpp
    src/rules/http.cpp
    src/utils/decEthernet.cpp
    src/utils/decIPv4.cpp
)

target_link_libraries(nids ${PCAP_LIBRARIES})

