CMAKE_MINIMUM_REQUIRED(VERSION 3.15)
PROJECT(THQUIC LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "-Wall -Wextra")

if (NOT EXISTS ${CMAKE_BINARY_DIR}/thirdparty)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/thirdparty)
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND} ${CMAKE_SOURCE_DIR}/thirdparty
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/thirdparty
)

execute_process(
    COMMAND ${CMAKE_COMMAND} --build . -j
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/thirdparty
)

set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${CMAKE_BINARY_DIR}/thirdparty/thirdparty)

find_package(spdlog REQUIRED)
find_package(Catch2 REQUIRED)

add_subdirectory(src)
add_subdirectory(app)