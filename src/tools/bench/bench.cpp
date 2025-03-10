/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Provides a very simple MsQuic API sample server and client application.

    The quicsample app implements a simple protocol (ALPN "sample") where the
    client connects to the server, opens a single bidirectional stream, sends
    some data and shuts down the stream in the send direction. On the server
    side all connections, streams and data are accepted. After the stream is
    shut down, the server then sends its own data and shuts down its send
    direction. The connection only shuts down when the 1 second idle timeout
    triggers.

    A certificate needs to be available for the server to function.

    On Windows, the following PowerShell command can be used to generate a self
    signed certificate with the correct settings. This works for both Schannel
    and OpenSSL TLS providers, assuming the KeyExportPolicy parameter is set to
    Exportable. The Thumbprint received from the command is then passed to this
    New-SelfSignedCertificate -DnsName $env:computername,localhost -FriendlyName MsQuic-Test -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable

    On Linux, the following command can be used to generate a self signed
    certificate that works with the OpenSSL TLS Provider. This can also be used
    for Windows OpenSSL, however we recommend the certificate store method above
    for ease of use. Currently key files with password protections are not
    supported. With these files, they can be passed to the sample with
    -cert_file:path/to/server.cert -key_file path/to/server.key

    openssl req  -nodes -new -x509  -keyout server.key -out server.cert

--*/
#include "client.h"
#include "server.h"
//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
// const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
// const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

//
// The UDP port used by the server side of the protocol.
//
// const uint16_t UdpPort = 4567;

//
// The default idle timeout period (1 second) used for the protocol.
//
// const uint64_t IdleTimeoutMs = 1000;

//
// The length of buffer sent over the streams in the protocol.
//
// const uint32_t SendBufferLength = 100;

//
// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
//
//const QUIC_API_TABLE* MsQuic;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
//HQUIC Registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
//HQUIC Configuration;


//
// The struct to be filled with TLS secrets
// for debugging packet captured with e.g. Wireshark.
//
// QUIC_TLS_SECRETS ClientSecrets = {0};

//
// The name of the environment variable being
// used to get the path to the ssl key log file.
//
//const char* SslKeyLogEnvVar = "SSLKEYLOGFILE";

void PrintUsage()
{
    printf(
        "\n"
        "quicsample runs a simple client or server.\n"
        "\n"
        "Usage:\n"
        "\n"
        "  quicsample.exe -client -unsecure -target:{IPAddress|Hostname} [-ticket:<ticket>]\n"
        "  quicsample.exe -server -cert_hash:<...>\n"
        "  quicsample.exe -server -cert_file:<...> -key_file:<...> [-password:<...>]\n"
        );
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
        PrintUsage();
    } else if (GetFlag(argc, argv, "client")) {
        RunClient(argc, argv);
    } else if (GetFlag(argc, argv, "server")) {
        RunServer(argc, argv);
    } else {
        PrintUsage();
    }

Error:

    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}
