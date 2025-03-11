# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(quicfilebench bench.cpp utils.cpp server.cpp client.cpp)
quic_tool_warnings(quicfilebench)
