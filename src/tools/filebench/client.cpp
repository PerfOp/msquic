#include "client.h"

#include <chrono>
#include <locale>
#include <string>

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
)
{
    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        //MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, NULL);
        //printf("davidxie: [strm][%p] gracefully shut down this stream\n", Stream);

        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", Stream);

        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        printf("[strm][%p] Client data received %d buffers %lld bytes\n", Stream, Event->RECEIVE.BufferCount, Event->RECEIVE.TotalBufferLength);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->StreamClose(Stream);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
ClientSend(
    _In_ HQUIC Connection
)
{
    const uint16_t NumStream = 1;
    // TODO: NumPayload > 1 (sending more than 1 files in a stream) is NOT working
    const uint16_t NumPayload = 1; // Send the payload for N times in one stream to simulate sending N large files
    QUIC_STATUS Status;
    HQUIC StreamArr[NumStream];
    QUIC_BUFFER* SendBuffers[NumStream];
    uint8_t* SendBuffersRaw[NumStream];
    char* Messages[NumStream];
    uint8_t* payload_ptr = NULL; // Write timestamp immediately before sending a file
    for (int i = 0; i < NumStream; i++)
    {
        Messages[i] = (char*) malloc(SendBufferLength);
        if (Messages[i] == NULL) {
            printf("Message Allocation Failed\n");
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        memset(Messages[i], 'a', SendBufferLength);
    }

    for (int i = 0; i < NumStream; i++)
    {
        SendBuffersRaw[i] = (uint8_t*)calloc(sizeof(QUIC_BUFFER) + SendBufferLength, 1);
        if (SendBuffersRaw[i] == NULL) {
            printf("Stream number %u : ", i);
            printf("SendBuffer allocation failed!\n");
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            for (int j = 0; j <= i; j = j + 1)
            {
                free(SendBuffers[j]);
            }
            goto Error;
        }
        //
        // Allocates and builds the buffer to send over the stream.
        //
        SendBuffers[i] = (QUIC_BUFFER*)SendBuffersRaw[i];
        SendBuffers[i]->Buffer = SendBuffersRaw[i] + sizeof(QUIC_BUFFER);
        // QUIC_BUFFER struct and QUIC_BUFFER.Buffer all points to a same memory allocation
        memcpy(SendBuffers[i]->Buffer, Messages[i], SendBufferLength);
        payload_ptr = SendBuffers[i]->Buffer;
        SendBuffers[i]->Length = SendBufferLength;
        printf("Stream number %u : ", i);
        printf("[strm][%p] Client sending data... %u bytes\n", StreamArr[i], SendBufferLength);
    }

    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //

    for (int i = 0; i < NumStream; i++)
    {
        if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, NULL, &StreamArr[i]))) {
            printf("Stream number %u : ", i);
            printf("StreamOpen failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    for (int i = 0; i < NumStream; i++)
    {
        printf("Stream number %u : ", i);
        printf("[strm][%p] Starting...\n", StreamArr[i]);
        //
        // Starts the bidirectional stream. By default, the peer is not notified of
        // the stream being started until data is sent on the stream.
        //
        if (QUIC_FAILED(Status = MsQuic->StreamStart(StreamArr[i], QUIC_STREAM_START_FLAG_NONE))) {
            printf("Stream number %u : ", i);
            printf("StreamStart failed, 0x%x!\n", Status);
            MsQuic->StreamClose(StreamArr[i]);
            goto Error;
        }
    }

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //

    for (int i = 0; i < NumStream; i++)
    {
        printf("Stream number %u begin sending a file \n", i);
        if (payload_ptr != NULL)
        {
            uint64_t nanosecond = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
            *(uint64_t*)payload_ptr = nanosecond; // Write nanosecond timestamp to first 8 bytes (64 bits) from the pointer
        }

        for (int j = 0; j < NumPayload - 1; j++)
        {
            if (QUIC_FAILED(Status = MsQuic->StreamSend(StreamArr[i], SendBuffers[i], 1, QUIC_SEND_FLAG_NONE, SendBuffers[i]))) {
                printf("Client StreamSend failed, 0x%x!\n", Status);
                free(SendBuffersRaw[i]);
                goto Error;
            }
        }

        // Last payload: send the buffer with FIN flag to gracefully shut down this stream.
        if (QUIC_FAILED(Status = MsQuic->StreamSend(StreamArr[i], SendBuffers[i], 1, QUIC_SEND_FLAG_FIN, SendBuffers[i]))) {
            printf("Client StreamSend failed, 0x%x!\n", Status);
            free(SendBuffersRaw[i]);
            goto Error;
        }
        printf("Stream number %u done sending a file \n", i);
    }

Error:
    for (int i = 0; i < NumStream; i++)
    {
        free(Messages[i]);
    }
    if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
}

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
)
{
    UNREFERENCED_PARAMETER(Context);

    if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
        const char* SslKeyLogFile = getenv(SslKeyLogEnvVar);
        if (SslKeyLogFile != NULL) {
            WriteSslKeyLogFile(SslKeyLogFile, &ClientSecrets);
        }
    }

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        ClientSend(Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        }
        else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", Connection);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->ConnectionClose(Connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        printf("[conn][%p] Client Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
            printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        printf("\n");
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Helper function to load a client configuration.
//
BOOLEAN
ClientLoadConfiguration(
    BOOLEAN Unsecure
)
{
    QUIC_SETTINGS Settings = { 0 };
    //
    // Configures the client's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

//
// Runs the client side of the protocol.
//
void
RunClient(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
)
{
    //
    // Load the client configuration based on the "unsecure" command line option.
    //
    if (!ClientLoadConfiguration(GetFlag(argc, argv, "unsecure"))) {
        return;
    }

    // Parse number of string
    const char* NumOfStreamStr = GetValue(argc, argv, "numstream");
    if (NumOfStreamStr == NULL)
    {
        printf("Must specify '-numstream' argument!\n");
        return;
    }

    // Try to convert string to int
    long int NumOfStream = strtol(NumOfStreamStr, nullptr, 10);
    if (NumOfStream < 1)
    {
        printf("-numstream should be at least 1\n");
        return;
    }

    // Value is successfully parsed, need to pass it to QUIC to open multiple stream in 1 connection
    uint8_t NumOfStreamParsed = (uint8_t)NumOfStream;

    QUIC_STATUS Status;
    const char* ResumptionTicketString = NULL;
    const char* SslKeyLogFile = getenv(SslKeyLogEnvVar);
    HQUIC Connection = NULL;

    // Create an MS Quic contex to pass number of streams in
    //
    // void* Context = NULL;
    // if (QUIC_FAILED(Status = MsQuic->SetContext(Connection, &Context))) {
    //     printf("SetContext failed, 0x%x!\n", Status);
    //     goto Error;
    // }

    //
    // Allocate a new connection object.
    //
    // TODO: try pass number of streams in ClientConnectionCallback function
    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, NULL, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != NULL) {
        //
        // If provided at the command line, set the resumption ticket that can
        // be used to resume a previous session.
        //
        uint8_t ResumptionTicket[10240];
        uint16_t TicketLength = (uint16_t)DecodeHexBuffer(ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket);
        if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET, TicketLength, ResumptionTicket))) {
            printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    if (SslKeyLogFile != NULL) {
        if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_TLS_SECRETS, sizeof(ClientSecrets), &ClientSecrets))) {
            printf("SetParam(QUIC_PARAM_CONN_TLS_SECRETS) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    //
    // Get the target / server name or IP from the command line.
    //
    const char* Target;
    if ((Target = GetValue(argc, argv, "target")) == NULL) {
        printf("Must specify '-target' argument!\n");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    printf("Using %u number of streams\n", NumOfStreamParsed);
    printf("[conn][%p] Connecting...\n", Connection);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, Target, UdpPort))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status) && Connection != NULL) {
        MsQuic->ConnectionClose(Connection);
    }
}
