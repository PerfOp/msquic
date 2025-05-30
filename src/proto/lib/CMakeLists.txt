# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    ProtoClient.cpp
    ProtoServer.cpp
    ProtoNetPerfMain.cpp
    Tcp.cpp
)

add_library(protolib STATIC ${SOURCES})

set_property(TARGET protolib PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}perf")

target_link_libraries(protolib PUBLIC)

target_link_libraries(protolib PRIVATE inc warnings)

target_include_directories(protolib PUBLIC ${CMAKE_CURRENT_LIST_DIR})

if(MSVC)
    target_compile_options(protolib PUBLIC /wd4459)
endif()
