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
#include <crazywolf/TlsLib.h>
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

static unsigned int cw_TlsLib_ServerPskCb(WOLFSSL* pSsl,
                                          const char* pRecvdIdentity,
                                          unsigned char* pKey,
                                          unsigned int keyBytes);
static unsigned int cw_TlsLib_ClientPskCb(WOLFSSL* pSsl,
                                          const char* pHint,
                                          char* pIdentity,
                                          unsigned int identityBytes,
                                          unsigned char* pKey,
                                          unsigned int keyBytes);

#if defined(CW_ENV_DEBUG_ENABLE)
/// @brief Error buffer for error texts.
static char cw_TlsLib_errBuffer[WOLFSSL_MAX_ERROR_SZ] = {0};
#endif // defined(CW_ENV_DEBUG_ENABLE)

//-----------------------------------------------------------------------------
// Global references
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
// Function definitions
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
//
// Init security library.
//
//-----------------------------------------------------------------------------
void CW_TlsLib_Startup(void)
{
#if defined(CW_ENV_DEBUG_ENABLE)
    wolfSSL_Debugging_ON();
#endif // defined(CW_ENV_DEBUG_ENABLE)

    wolfSSL_Init();
} // End: CW_TlsLib_Startup()


//------------------------------------------------------------------------------
//
// Creates a security context. Returns security context handle.
//
//------------------------------------------------------------------------------
void* CW_TlsLib_CreateSecurityContext(bool isServer,
                                      const char* pCaCertPath,
                                      TlsLibFileType_t caCertFileType,
                                      const char* pDevCertPath,
                                      TlsLibFileType_t devCertFileType,
                                      const char* pDevKeyPath,
                                      TlsLibFileType_t devKeyFileType,
                                      const char* pCipherList,
                                      bool isTls)
{
    WOLFSSL_METHOD* pMethod = NULL;
    if (isServer)
    {
        if (isTls)
        {
            pMethod = wolfTLSv1_2_server_method();
        }
        else
        {
            pMethod = wolfDTLSv1_2_server_method();
        }
    }
    else
    {
        if (isTls)
        {
            pMethod = wolfTLSv1_2_client_method();
        }
        else
        {
            pMethod = wolfDTLSv1_2_client_method();
        }
    }

    if (pMethod == NULL)
    {
        CW_Common_Die("wolf method error");
    }

    WOLFSSL_CTX* pCtx = wolfSSL_CTX_new(pMethod);
    if (pCtx == NULL)
    {
        CW_Common_Die("wolf ctx error");
    }
    if (isServer)
    {
        wolfSSL_CTX_set_psk_server_callback(pCtx, &cw_TlsLib_ServerPskCb);
        wolfSSL_CTX_use_psk_identity_hint(pCtx, "");
    }
    else
    {
        wolfSSL_CTX_set_psk_client_callback(pCtx, &cw_TlsLib_ClientPskCb);
    }

    if (wolfSSL_CTX_load_verify_locations(pCtx, pCaCertPath, 0) != WOLFSSL_SUCCESS)
    {
        CW_Common_Die("invalid cert path");
    }

    if (pDevCertPath != NULL)
    {
        int format = devCertFileType == TLSLIB_FILE_TYPE_DER ? WOLFSSL_FILETYPE_ASN1 : WOLFSSL_FILETYPE_PEM;

        if (wolfSSL_CTX_use_certificate_file(pCtx,
                                             pDevCertPath,
                                             format) != WOLFSSL_SUCCESS)
        {
            printf("Device cert load error: %s", pDevCertPath);
            CW_Common_Die("");
        }
    }
    else
    {
        printf("Warning: Device certificate not set.");
    }

    if (pDevKeyPath != NULL)
    {
        int format = devKeyFileType == TLSLIB_FILE_TYPE_DER ? WOLFSSL_FILETYPE_ASN1 : WOLFSSL_FILETYPE_PEM;

        if (wolfSSL_CTX_use_PrivateKey_file(pCtx, pDevKeyPath, format) != WOLFSSL_SUCCESS)
        {
            printf("Device key load error: %s", pDevKeyPath);
            CW_Common_Die("");
        }
    }
    else
    {
        printf("Warning: Device key not set.");
    }

    if (!wolfSSL_CTX_set_cipher_list(pCtx, pCipherList))
    {
        CW_Common_Die("wolf cipher list error");
    }

    return pCtx;
} // End: CW_TlsLib_CreateSecurityContext()


//------------------------------------------------------------------------------
//
// Makes a sd secure. Returns secure sd context handle.
//
//--------------------------------------------------------------------------
void* CW_TlsLib_MakeSocketSecure(int sd,
                                 void* pSecureCtx,
                                 void* pPeerAddr,
                                 size_t peerAddrSize)
{
    WOLFSSL_CTX* pCtx = (WOLFSSL_CTX*)pSecureCtx;
    WOLFSSL* pSsl = wolfSSL_new(pCtx);
    if (pSsl == NULL)
    {
        CW_Common_Die("wolf ssl error");
    }

    if (wolfSSL_set_fd(pSsl, sd) != WOLFSSL_SUCCESS)
    {
        CW_Common_Die("wolf set_fd error");
    }

    #if defined(CW_ENV_TEST_DTLS)
        wolfSSL_dtls_set_peer(pSsl, pPeerAddr, peerAddrSize);
    #else
        (void)pPeerAddr;
    #endif

    return (void*)pSsl;
} // End: CW_TlsLib_MakeSocketSecure()


//------------------------------------------------------------------------------
//
// Unmakes security of a sd. Frees secure sd context per
// its handle.
//
//------------------------------------------------------------------------------
void CW_TlsLib_UnmakeSocketSecure(int sd, void* pSecureSocketCtx)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;
    wolfSSL_shutdown(pSsl);
    wolfSSL_free(pSsl);
} // End: CW_TlsLib_UnmakeSocketSecure()


//------------------------------------------------------------------------------
//
// Destroys a security context.
//
//------------------------------------------------------------------------------
void CW_TlsLib_DestroySecureContext(void* pSecureCtx)
{
    WOLFSSL_CTX* pCtx = (WOLFSSL_CTX*)pSecureCtx;
    wolfSSL_CTX_free(pCtx);
} // End: CW_TlsLib_DestroySecureContext()


//------------------------------------------------------------------------------
//
// Performs client handshake.
//
//------------------------------------------------------------------------------
void CW_TlsLib_ClientHandshake(int sd, void* pSecureSocketCtx)
{
    (void)sd;
    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;
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
#if defined(CW_ENV_DEBUG_ENABLE)
        printf("ssl connect error %d, %s\n", err,
            wolfSSL_ERR_error_string(err, cw_TlsLib_errBuffer));
#endif // defined(CW_ENV_DEBUG_ENABLE)
        CW_Common_Die("ssl connect failed");
    }
} // End: CW_TlsLib_ClientHandshake()


//------------------------------------------------------------------------------
//
// Performs server handshake.
//
//------------------------------------------------------------------------------
int CW_TlsLib_ServerHandshake(int sd, void* pSecureSocketCtx)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;
    int ret = 0;
    int err = 0;
    do
    {
        err = 0;
        ret = wolfSSL_accept(pSsl);
        if (ret != WOLFSSL_SUCCESS)
        {
            err = wolfSSL_get_error(pSsl, 0);
        }
    } while (err == WC_PENDING_E);

    if (ret != WOLFSSL_SUCCESS)
    {
#if defined(CW_ENV_DEBUG_ENABLE)
        printf("wolf accept error = %d, %s\n", err,
               wolfSSL_ERR_error_string(err, cw_TlsLib_errBuffer));
#endif // defined(CW_ENV_DEBUG_ENABLE)
        wolfSSL_free(pSsl);
        ret = -1;
    }


    return (ret != WOLFSSL_SUCCESS) ? -1 : 0;
} // End: CW_TlsLib_ServerHandshake()


//------------------------------------------------------------------------------
//
// Sends data securely until everything has been sent in a loop.
//
//------------------------------------------------------------------------------
void CW_TlsLib_SendAll(int sd,
                       void* pSecureSocketCtx,
                       uint8_t* pData,
                       size_t dataBytes)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;
    int err = 0;
    int offset = 0;
    while (offset < dataBytes)
    {
        do
        {
            int ret = wolfSSL_write(pSsl,
                                    pData + offset,
                                    (int)dataBytes - offset);
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
} // End: CW_TlsLib_SendAll()


void CW_TlsLib_SendToAll(int sd,
                         void* pSecureSocketCtx,
                         uint32_t ip4Addr,
                         uint16_t port,
                         uint8_t* pData,
                         size_t dataBytes)
{
    (void)ip4Addr;
    (void)port;

    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;
    int err = 0;
    int offset = 0;
    while (offset < dataBytes)
    {
        do
        {
            int ret = wolfSSL_write(pSsl,
                                    pData + offset,
                                    (int)dataBytes - offset);
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


//------------------------------------------------------------------------------
//
// Sends data securely until everything has been sent in a loop but
// byte by byte.
//
//------------------------------------------------------------------------------
void CW_TlsLib_SendOneByOneByte(int sd,
                                void* pSecureSocketCtx,
                                uint8_t* pData,
                                size_t dataBytes)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;
    int err = 0;
    uint32_t offset = 0;
    while (offset < dataBytes)
    {
        do
        {
#if defined(CW_ENV_DEBUG_ENABLE)
            printf("Sending %u / %zu: %c (%02x)\n",
                   offset+1,
                   dataBytes,
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
} // End: CW_TlsLib_SendOneByOneByte()


//------------------------------------------------------------------------------
//
// Sends data securely at once. No loop involved.
//
//------------------------------------------------------------------------------
void CW_TlsLib_SendAllInOne(int sd,
                            void* pSecureSocketCtx,
                            uint8_t* pData,
                            size_t dataBytes)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;

    int ret = wolfSSL_write(pSsl, pData, (int)dataBytes);
    if (ret != dataBytes)
    {
        int err = wolfSSL_get_error(pSsl, 0);
#if defined(CW_ENV_DEBUG_ENABLE)
        printf("ssl write error %d, %s\n", err,
               wolfSSL_ERR_error_string(err, cw_TlsLib_errBuffer));
#endif // defined(CW_ENV_DEBUG_ENABLE)
        CW_Common_Die("Wolfssl ERROR!");
    }
} // End: CW_TlsLib_SendOneByOneByte()



//------------------------------------------------------------------------------
//
// reads data of specified length
//
//------------------------------------------------------------------------------
int CW_TlsLib_Recv(int sd,
                   void* pSecureSocketCtx,
                   uint8_t* pData,
                   size_t dataBytes)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;

    int offset = 0;
    int err = 0;

    // read while not [len] bytes read or some connection error
    do
    {
        err = 0;
        int ret = wolfSSL_read(pSsl, pData + offset, (int)dataBytes - offset);
        if (ret <= 0)
        {
            err = wolfSSL_get_error(pSsl, 0);
        }
        else
        {
            offset += ret;
        }
    } while (offset < dataBytes &&
            (err == 0 || err == WC_PENDING_E));

    if (offset == dataBytes)
    {
        return 0;
    }

#if defined(CW_ENV_DEBUG_ENABLE)
    printf("wolfSSL read error %d, %s!\n", err, wolfSSL_ERR_error_string(err, cw_TlsLib_errBuffer));
#endif // defined(CW_ENV_DEBUG_ENABLE)
    return -1;
}

static unsigned int cw_TlsLib_ServerPskCb(WOLFSSL* pSsl,
                                          const char* pRecvdIdentity,
                                          unsigned char* pKey,
                                          unsigned int keyBytes)
{
    (void)pSsl;

    const char* pOurPskIdentity = CW_Common_GetPskIdentity();
    size_t ourPskBytes = 0;
    uint8_t* pOurPsk = CW_Common_GetPsk(&ourPskBytes);

    if (XSTRCMP(pRecvdIdentity, pOurPskIdentity) != 0)
    {
        return 0;
    }

    if (keyBytes >= ourPskBytes)
    {
        memcpy(pKey, pOurPsk, ourPskBytes);
    }
    else
    {
        return 0;
    }

    return (unsigned int)ourPskBytes;
}

static unsigned int cw_TlsLib_ClientPskCb(WOLFSSL* pSsl,
                                          const char* pHint,
                                          char* pIdentity,
                                          unsigned int identityBytes,
                                          unsigned char* pKey,
                                          unsigned int keyBytes)
{
    (void)pSsl;
    (void)pHint;

    const char* pOurPskIdentity = CW_Common_GetPskIdentity();
    size_t ourPskBytes = 0;
    uint8_t* pOurPsk = CW_Common_GetPsk(&ourPskBytes);

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    XSTRNCPY(pIdentity, pOurPskIdentity, identityBytes);

    if (keyBytes >= ourPskBytes)
    {
        memcpy(pKey, pOurPsk, ourPskBytes);
    }
    else
    {
        return 0;
    }

    return (unsigned int)ourPskBytes;

}

//-----------------------------------------------------------------------------
//
// Shut the security library down.
//
//-----------------------------------------------------------------------------
void CW_TlsLib_Shutdown(void)
{
    wolfSSL_Cleanup();
} // End: CW_TlsLib_Shutdown()

void *XMALLOC(size_t n, void* heap, int type)
{
    (void)heap;
    (void)type;
    return CW_Common_Malloc(n);
}

void *XREALLOC(void *p, size_t n, void* heap, int type)
{
    (void)heap;
    (void)type;
    return CW_Common_Realloc(p,n);
}

void XFREE(void *p, void* heap, int type)
{
    (void)heap;
    (void)type;
    return CW_Common_Free(p);
}
