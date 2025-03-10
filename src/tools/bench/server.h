#pragma once

#include "utils.h"
void
ServerSend(
    _In_ HQUIC Stream
);

//
// The server's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
);

//
// The server's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
);

//
// The server's callback for listener events from MsQuic.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
);


//
// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
//
BOOLEAN
ServerLoadConfiguration(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
);

//
// Runs the server side of the protocol.
//
void
RunServer(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
);
