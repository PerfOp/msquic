#pragma once

#include "utils.h"

//
// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ClientStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
);

void
ClientSend(
    _In_ HQUIC Connection
);

//
// The clients's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
);

//
// Helper function to load a client configuration.
//
BOOLEAN
ClientLoadConfiguration(
    BOOLEAN Unsecure
);

//
// Runs the client side of the protocol.
//
void
RunClient(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
);
