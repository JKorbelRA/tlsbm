//==============================================================================
///
/// @file client.c
///
///
/// @brief A test TLS client using wolfSSL library.
///
/// Copyright (c) 2023 Rockwell Automation Technologies, Inc.
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

#include <crazywolf/Common.h>
#include <crazywolf/Tlslib.h>
#include <crazywolf/Environment.h> // Generated header, look into CMake.

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

char cw_Tlslib_errBuffer[2048] = {0};

//-----------------------------------------------------------------------------
// Global references
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
// Function definitions
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
///
/// @brief Init security library.
///
//-----------------------------------------------------------------------------
void CW_Tlslib_Startup(void)
{
#if defined(CW_ENV_DEBUG_ENABLE)
    wolfSSL_Debugging_ON();
#endif // defined(CW_ENV_DEBUG_ENABLE)

    wolfSSL_Init();
} // End: CW_Lib_Startup()

void* CW_Tlslib_CreateSecureContext(void)
{
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

    return pCtx;
}

void* CW_Tlslib_MakeSocketSecure(int socket, void* pSecureCtx)
{
    WOLFSSL_CTX* pCtx = (WOLFSSL_CTX*)pSecureCtx;
    WOLFSSL* pSsl = wolfSSL_new(pCtx);
    if (pSsl == NULL)
    {
        CW_Common_Die("wolf ssl error");
    }

    if (wolfSSL_set_fd(pSsl, socket) != WOLFSSL_SUCCESS)
    {
        CW_Common_Die("wolf set_fd error");
    }

    return (void*)pSsl;
}

void CW_Tlslib_UnmakeSocketSecure(int socket, void* pSocketSecureCtx)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSocketSecureCtx;
    wolfSSL_shutdown(pSsl);
    wolfSSL_free(pSsl);
}

void CW_Tlslib_DestroySecureContext(void* pSecureCtx)
{
    WOLFSSL_CTX* pCtx = (WOLFSSL_CTX*)pSecureCtx;
    wolfSSL_CTX_free(pCtx);
}

void CW_TlsLib_Handshake(void* pCtx)
{
    WOLFSSL* pSsl = (WOLFSSL*)pCtx;
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


void CW_Tlslib_SendAll(int socket,
                       void* pSocketSecureCtx,
                       uint8_t* pData,
                       size_t dataBytes)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSocketSecureCtx;
    int err = 0;
    uint32_t offset = 0;
    while (offset < dataBytes)
    {
        do
        {
            int ret = wolfSSL_write(pSsl,
                                    pData + offset,
                                    dataBytes - offset);
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
} // End: CW_Tlslib_SendAll()


void CW_Tlslib_SendOneByOneByte(int socket,
                                void* pSocketSecureCtx,
                                uint8_t* pData,
                                size_t dataBytes)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSocketSecureCtx;
    int err = 0;
    uint32_t offset = 0;
    while (offset < dataBytes)
    {
        do
        {
#if defined(CW_ENV_DEBUG_ENABLE)
            printf("Sending %u / %u: %c (%02x)\n",
                   offset+1, dataBytes,
                   pData[offset],
                   pData[offset]);
#endif // defined(CW_ENV_DEBUG_ENABLE)
            int ret = wolfSSL_write(pSsl, &pData[offset], 1);
            if (ret <= 0)
            {
                err = wolfSSL_get_error(pSsl, 0);
                offset = dataBytes;
            }
            else
            {
                offset += 1;
            }
        } while (err == WC_PENDING_E);
    }
} // End: CW_Tlslib_SendOneByOneByte()


void CW_Tlslib_SendAllInOne(int socket,
                            void* pSocketSecureCtx,
                            uint8_t* pData,
                            size_t dataBytes)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSocketSecureCtx;

    int ret = wolfSSL_write(pSsl, pData, dataBytes);
    if (ret != dataBytes)
    {
        int err = wolfSSL_get_error(pSsl, 0);
#if defined(CW_ENV_DEBUG_ENABLE)
        printf("ssl write error %d, %s\n", err,
               wolfSSL_ERR_error_string(err, cw_Tlslib_errBuffer));
#endif // defined(CW_ENV_DEBUG_ENABLE)
        CW_Common_Die("Wolfssl ERROR!");
    }
} // End: CW_Tlslib_SendOneByOneByte()


//-----------------------------------------------------------------------------
///
/// @brief Shut the security library down.
///
//-----------------------------------------------------------------------------
void CW_Tlslib_Shutdown(void)
{
    wolfSSL_Cleanup();
} // End: CW_Lib_Shutdown()


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

