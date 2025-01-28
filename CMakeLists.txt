cmake_minimum_required(VERSION 3.30)
project(HyperionDumper)

set(CMAKE_CXX_STANDARD 20)

add_executable(${PROJECT_NAME} main.cpp
        PEDumper.cpp
        PEDumper.hpp

        Dumper.hpp)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/capstone")
target_include_directories(${PROJECT_NAME} PRIVATE "Dependencies")

target_link_libraries(${PROJECT_NAME} PUBLIC
        capstone
)