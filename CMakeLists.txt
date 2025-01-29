cmake_minimum_required(VERSION 3.30)
project(HyperionDumper)

set(CMAKE_CXX_STANDARD 20)

add_executable(${PROJECT_NAME} main.cpp
        PEDumper.cpp
        PEDumper.hpp

        Dumper.hpp
        Dissassembler.cpp
        Dissassembler.hpp
        PatchTasks/OpaquePredicateResolver.cpp
        PatchTasks/OpaquePredicateResolver.hpp
        PatternAnalyzer.cpp
        PatternAnalyzer.hpp)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/zydis")

target_include_directories(${PROJECT_NAME} PRIVATE "Dependencies")

target_link_libraries(${PROJECT_NAME} PRIVATE
        Zydis
)