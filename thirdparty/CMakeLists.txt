cmake_minimum_required(VERSION 3.15)
project(thrid_party)
include(ExternalProject)

ExternalProject_Add(spdlog
    GIT_REPOSITORY "https://github.com/gabime/spdlog"
    GIT_TAG "v1.8.5"
    PREFIX "thirdparty"
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=Release
)

ExternalProject_Add(Catch2
    GIT_REPOSITORY "https://github.com/catchorg/Catch2"
    GIT_TAG "v2.13.6"
    PREFIX "thirdparty"
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=Release
)

