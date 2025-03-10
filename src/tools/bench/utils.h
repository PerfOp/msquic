#pragma once

#define _CRT_SECURE_NO_WARNINGS 1

#ifdef _WIN32
//
// The conformant preprocessor along with the newest SDK throws this warning for
// a macro in C mode. As users might run into this exact bug, exclude this
// warning here. This is not an MsQuic bug but a Windows SDK bug.
//
#pragma warning(disable:5105)
#include <share.h>
#endif
#include "msquic.h"
#include <stdio.h>
#include <stdlib.h>

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
extern const QUIC_REGISTRATION_CONFIG RegConfig;

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
extern const QUIC_BUFFER Alpn;

//
// The UDP port used by the server side of the protocol.
//
extern const uint16_t UdpPort;

//
// The default idle timeout period (1 second) used for the protocol.
//
extern const uint64_t IdleTimeoutMs;

//
// The length of buffer sent over the streams in the protocol.
//
extern const uint32_t SendBufferLength;

//
// The QUIC handle to the registration object. This is the top level API object
//
// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
//
extern const QUIC_API_TABLE* MsQuic;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
extern HQUIC Registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
extern HQUIC Configuration;


//
// The struct to be filled with TLS secrets
// for debugging packet captured with e.g. Wireshark.
//
extern QUIC_TLS_SECRETS ClientSecrets;

//
// The name of the environment variable being
// used to get the path to the ssl key log file.
//
extern const char* SslKeyLogEnvVar;

//
// Helper functions to look up a command line arguments.
//
BOOLEAN
GetFlag(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
);

_Ret_maybenull_ _Null_terminated_ const char*
GetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
);

uint8_t
DecodeHexChar(
    _In_ char c
);
//
// Helper function to convert a string of hex characters to a byte buffer.
//
uint32_t
DecodeHexBuffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
    uint8_t* OutBuffer
);

void
EncodeHexBuffer(
    _In_reads_(BufferLen) uint8_t * Buffer,
    _In_ uint8_t BufferLen,
    _Out_writes_bytes_(2 * BufferLen) char* HexString
);

void
WriteSslKeyLogFile(
    _In_z_ const char* FileName,
    _In_ QUIC_TLS_SECRETS * TlsSecrets
);
