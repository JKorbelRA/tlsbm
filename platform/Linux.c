//==============================================================================
///
/// @file client.c
///
///
/// @brief A test TLS client using wolfSSL library.
///
/// Copyright (c) 2022 Rockwell Automation Technologies, Inc.
/// All rights reserved.
//==============================================================================

//------------------------------------------------------------------------------
// Include files
//------------------------------------------------------------------------------
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>

#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#endif

#include "Common.h"
// wolfSSL
#include <wolfssl/ssl.h>

//-----------------------------------------------------------------------------
// Constants
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Macros
//-----------------------------------------------------------------------------



//-----------------------------------------------------------------------------
// Local data types
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Local constants
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Global references
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Forward function declarations
//-----------------------------------------------------------------------------

static int cw_Client_TcpConnect(int* pSocket,
                                const char* pIp,
                                uint16_t port);

static int cw_Client_TlsClient(char* pSrvIP,
                               uint16_t port,
                               char* pCertDirPath);

//-----------------------------------------------------------------------------
// Variable definitions
//-----------------------------------------------------------------------------

typedef union
{
    struct
    {
        uint16_t payloadBytesBe;
        uint8_t payload[UINT16_MAX];
        uint8_t zero;
    } str;

    uint8_t msg[UINT16_MAX + sizeof(uint16_t) + sizeof(uint8_t)];
} Msg_t;

static Msg_t cw_Client_msg;
static char cw_Client_errBuffer[4096];

//-----------------------------------------------------------------------------
// Function definitions
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
///
/// @brief init connection socket
///
/// @param[out] pSocket - pointer to socket
/// @param[in] pIp - server IP address
/// @param[in] port - port
///
/// @return 0 on success
///
//-----------------------------------------------------------------------------
static int cw_Client_TcpConnect(int* pSocket, const char* pIp, uint16_t port)
{
    *pSocket = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (*pSocket == -1) //INVALID_SOCKET undef in Unix
    {
        CW_Common_Die("can't get socket");
    }

    struct sockaddr_in srvAddr;
    memset(&srvAddr, sizeof(srvAddr), 0);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(port);
    srvAddr.sin_addr.s_addr = inet_addr(pIp);

    if (connect(*pSocket, (struct sockaddr*)&srvAddr, sizeof(srvAddr)) == -1)
    {
        CW_Common_Die("socket connect failed");
    }

    return 0;
} // End: cw_Client_TcpConnect()


static void cw_Client_WolfConnect(WOLFSSL* pSsl)
{
    int ret = 0;
    int err = 0;
    do {
        err = 0;
        ret = wolfSSL_connect(pSsl);
        if (ret != WOLFSSL_SUCCESS) {
            err = wolfSSL_get_error(pSsl, 0);
        }
    } while (err == WC_PENDING_E);


    if (ret != WOLFSSL_SUCCESS)
    {
        printf("ssl connect error %d, %s\n", err,
            wolfSSL_ERR_error_string(err, cw_Client_errBuffer));
        CW_Common_Die("ssl connect failed");
    }
}


static void cw_Client_WolfSendHappy(WOLFSSL* pSsl)
{
    uint32_t msgBytes = ntohs(cw_Client_msg.str.payloadBytesBe) + 2;

    int err = 0;
    uint32_t offset = 0;
    while (offset < msgBytes)
    {
        do
        {
            int ret = wolfSSL_write(pSsl,
                                    cw_Client_msg.msg + offset,
                                    msgBytes - offset);
            if (ret <= 0)
            {
                err = wolfSSL_get_error(pSsl, 0);
            }
            else
            {
                offset += ret;
            }
        } while (err == WC_PENDING_E);
    }
}


static void cw_Client_WolfSend1by1(WOLFSSL* pSsl)
{
    uint32_t msgBytes = ntohs(cw_Client_msg.str.payloadBytesBe) + 2;

    int err = 0;
    uint32_t offset = 0;

    while (offset < msgBytes)
    {
        do
        {
            printf("Sending %u / %u: %c (%02x)\n", offset+1, msgBytes, cw_Client_msg.msg[offset], cw_Client_msg.msg[offset]);
            int ret = wolfSSL_write(pSsl, &cw_Client_msg.msg[offset], 1);
            if (ret <= 0)
            {
                err = wolfSSL_get_error(pSsl, 0);
                offset = msgBytes;
            }
            else
            {
                offset += 1;
            }
        } while (err == WC_PENDING_E);
    }
}


static void cw_Client_WolfSendErrorNow(WOLFSSL* pSsl)
{
    int msgBytes = ntohs(cw_Client_msg.str.payloadBytesBe) + 2;

    int ret = wolfSSL_write(pSsl, cw_Client_msg.msg, msgBytes);
    if (ret != msgBytes)
    {
        int err = wolfSSL_get_error(pSsl, 0);
        printf("ssl write error %d, %s\n", err,
            wolfSSL_ERR_error_string(err, cw_Client_errBuffer));
        CW_Common_Die("Wolfssl ERROR!");
    }
}

#define CW_CLIENT_FLAG_NO_BASIC 0x01
#define CW_CLIENT_FLAG_NO_1BY1 0x02
#define CW_CLIENT_FLAG_NO_ATONCE 0x04

#define CW_CLIENT_TESTSTR(payload, flags)\
    cw_Client_SendTestMsg(pSsl, sizeof(payload) - 1, payload, flags)
#define CW_CLIENT_TESTMSG(payloadBytes, payload, flags)\
    cw_Client_SendTestMsg(pSsl, payloadBytes, payload, flags)


static void cw_Client_SendTestMsg(WOLFSSL* pSsl,
                                  uint16_t payloadBytes,
                                  const char* pPayload,
                                  uint8_t flags)
{
    cw_Client_msg.str.payloadBytesBe = htons(payloadBytes);
    cw_Client_msg.str.zero = 0;
    memcpy(cw_Client_msg.str.payload, pPayload, payloadBytes);

    printf("Testing following message (%u bytes):\n%s\n",
           payloadBytes,
           pPayload);

    if ((flags & CW_CLIENT_FLAG_NO_BASIC) == 0)
    {
        printf("Basic test running.\n");
        cw_Client_WolfSendHappy(pSsl);
        printf("Basic test DONE.\n");
    }
    else
    {
        printf("Basic test disabled.\n");
    }

    if ((flags & CW_CLIENT_FLAG_NO_1BY1) == 0)
    {
        printf("1-by-1 test running.\n");
        cw_Client_WolfSend1by1(pSsl);
        printf("1-by-1 test DONE.\n");
    }
    else
    {
        printf("1-by-1 test disabled.\n");
    }

    if ((flags & CW_CLIENT_FLAG_NO_ATONCE) == 0)
    {
        printf("All-at-once test running.\n");
        cw_Client_WolfSendErrorNow(pSsl);
        printf("All-at-once test DONE.\n");
    }
    else
    {
        printf("All-at-once test disabled.\n");
    }
}

//-----------------------------------------------------------------------------
///
/// @brief main client function, reads inputBuffer from stdin and send it to the SSL server
///
/// @param[in] pSrvIP - server IP
/// @param[in] port - comm port
/// @param[in] pCertDirPath - path to certificates
/// @return 0 on success
///
//-----------------------------------------------------------------------------
static int cw_Client_TlsClient(char* pSrvIP, uint16_t port, char* pCertDirPath)
{
    printf("Connecting server\n");
    int socket = 0;
    if (cw_Client_TcpConnect(&socket, pSrvIP, port))
    {
        CW_Common_Die("can't connect to server");
    }

    printf("Server %s:%d connected\n", pSrvIP, port);
    WOLFSSL_METHOD* pMethod = wolfTLSv1_2_client_method();
    if (pMethod == NULL)
    {
        CW_Common_Die("wolf method error");
    }

    WOLFSSL_CTX* pCtx = wolfSSL_CTX_new(pMethod);
    if (pCtx == NULL)
    {
        CW_Common_Die("wolf ctx error");
    }

    if (wolfSSL_CTX_load_verify_locations(pCtx, "cert.pem", 0) != WOLFSSL_SUCCESS)
    {
        CW_Common_Die("invalid cert path");
    }

    // TODO check if exists first or try others if fails?
    if (!wolfSSL_CTX_set_cipher_list(pCtx, "ECDHE-ECDSA-AES128-SHA256"))
    {
        CW_Common_Die("wolf cipher list error");
    }

    WOLFSSL* pSsl = wolfSSL_new(pCtx);
    if (pSsl == NULL)
    {
        CW_Common_Die("wolf ssl error");
    }

    if (wolfSSL_set_fd(pSsl, socket) != WOLFSSL_SUCCESS)
    {
        CW_Common_Die("wolf set_fd error");
    }

    cw_Client_WolfConnect(pSsl);

    // large buffers allocated on heap
    static char errBuffer[WOLFSSL_MAX_ERROR_SZ];


    // Let's test!

    printf("Test case 0: Mic test\n");
    CW_CLIENT_TESTSTR("Hi", 0);
    CW_CLIENT_TESTSTR("Hello", 0);
    CW_CLIENT_TESTSTR("Testing Testing", 0);


    printf("Test case 1: Smallest message\n");
    CW_CLIENT_TESTSTR("", 0);

    printf("Test case 2: Largest message\n");
    cw_Client_msg.str.payloadBytesBe = UINT16_MAX;
    for (uint16_t i = 0; i < UINT16_MAX; i++)
    {
        cw_Client_msg.str.payload[i] = 'a';
    }
    for (uint32_t i = 0; i < UINT16_MAX+2; i++)
    {
        printf("%c\n", cw_Client_msg.msg[i]);
    }

    printf("\t HAPPY\n");
    cw_Client_WolfSendHappy(pSsl);
    printf("\t one-by-one\n");
    cw_Client_WolfSend1by1(pSsl);
    printf("\t at once!\n");
    cw_Client_WolfSendErrorNow(pSsl);
    printf("\t DONE!\n");

    printf("Test case 3: Zeroes and newlines\n");
    cw_Client_msg.str.payloadBytesBe = htons(4);
    cw_Client_msg.str.payload[0] = '0';
    cw_Client_msg.str.payload[1] = '\0';
    cw_Client_msg.str.payload[2] = 'n';
    cw_Client_msg.str.payload[3] = '\n';

    printf("\t HAPPY\n");
    cw_Client_WolfSendHappy(pSsl);
    printf("\t one-by-one\n");
    cw_Client_WolfSend1by1(pSsl);
    printf("\t at once!\n");
    cw_Client_WolfSendErrorNow(pSsl);
    printf("\t DONE!\n");


    wolfSSL_shutdown(pSsl);
    wolfSSL_free(pSsl);
    wolfSSL_CTX_free(pCtx);

    CloseSocket(socket);
    return 0;
} // End: cw_Client_TlsClient()


//------------------------------------------------------------------------------
///
/// @brief Entry point for the simple SSL Client
///
//------------------------------------------------------------------------------
int main(int argc, char** argv)
{
    uint16_t port = SIMPLE_SSL_PORT;
    char* pServerIP = SIMPLE_SSL_SERVER_ADDR;
    char* pCertPath = SIMPLE_SSL_CERT_PATH;

//wolfSSL_Debugging_ON();

    // check args count
    // TODO enable to change port by cmd args
    if (argc == 2)
    {
        // use argv[1] as server IP
        pServerIP = argv[1];
    }
    else
    {
        // tell user, server IP can be set
        printf("USAGE: <simpleClient.exe> [serverIP], running with default %s\n", pServerIP);
    }

#ifdef WIN32
    WSADATA wsaData;
    if (WSAStartup(0x0002, &wsaData) != NO_ERROR)
    {
        return 1;
    }
#endif // WIN32

    int result = 1;
    wolfSSL_Init();
    result = cw_Client_TlsClient(pServerIP, port, pCertPath);
    wolfSSL_Cleanup();
    return result;
} // End: main()

