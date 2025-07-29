add_executable(nids
    src/main.cpp
    src/parsers/ethernet.cpp
)

target_include_directories(nids PRIVATE include)
