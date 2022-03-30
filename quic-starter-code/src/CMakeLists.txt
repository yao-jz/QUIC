add_library(lib${PROJECT_NAME}
    "context/quic.cc"
    "context/connection_id.cc"

    "utils/random.cc"
    "utils/socket.cc"
    "utils/log.cc"
    "utils/variable_codec.cc"
)

target_include_directories(lib${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(lib${PROJECT_NAME} PUBLIC
    spdlog::spdlog
)