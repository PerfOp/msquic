# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    protomain.cpp
)

add_executable(protoperf ${SOURCES} histogram/hdr_histogram.c)

set_property(TARGET protoperf PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}perf")

target_link_libraries(protoperf inc warnings protolib msquic)

if (BUILD_SHARED_LIBS)
    target_link_libraries(protoperf msquic_platform)
endif()

target_link_libraries(protoperf logging base_link)
