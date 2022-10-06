add_executable(${PROJECT_NAME}_pingpong_server
    "pingpong_server.cc"
)

target_link_libraries(${PROJECT_NAME}_pingpong_server
    lib${PROJECT_NAME}
)

add_executable(${PROJECT_NAME}_pingpong_client
    "pingpong_client.cc"
)

target_link_libraries(${PROJECT_NAME}_pingpong_client
    lib${PROJECT_NAME}
)

add_executable(${PROJECT_NAME}_cc_server
    "cc_server.cc"
)

target_link_libraries(${PROJECT_NAME}_cc_server
    lib${PROJECT_NAME}
)

add_executable(${PROJECT_NAME}_cc_client
    "cc_client.cc"
)

target_link_libraries(${PROJECT_NAME}_cc_client
    lib${PROJECT_NAME}
)
