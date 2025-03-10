# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(quicbench bench.cpp utils.cpp server.cpp client.cpp)
quic_tool_warnings(quicbench)
