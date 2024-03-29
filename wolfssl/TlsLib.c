//==============================================================================
///
/// @file client.c
///
///
/// @brief A test TLS client using wolfSSL library.
///
///
/// MIT License
///
/// Copyright (c) 2023 Rockwell Automation, Inc.
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///
//==============================================================================

//------------------------------------------------------------------------------
// Include files
//------------------------------------------------------------------------------
#include "../include/tlsbm/TlsLib.h"

#include <stdio.h>

#include <tlsbm/Environment.h> // Generated header, look into CMake.

// wolfSSL
#include <wolfssl/ssl.h>
#include "../include/tlsbm/Common.h"

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

static unsigned int tlsbm_TlsLib_ServerPskCb(WOLFSSL* pSsl,
                                          const char* pRecvdIdentity,
                                          unsigned char* pKey,
                                          unsigned int keyBytes);
static unsigned int tlsbm_TlsLib_ClientPskCb(WOLFSSL* pSsl,
                                          const char* pHint,
                                          char* pIdentity,
                                          unsigned int identityBytes,
                                          unsigned char* pKey,
                                          unsigned int keyBytes);

#if defined(TLSBM_ENV_DEBUG_ENABLE)
/// @brief Error buffer for error texts.
static char tlsbm_TlsLib_errBuffer[WOLFSSL_MAX_ERROR_SZ] = {0};
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)

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
void TLSBM_TlsLib_Startup(void)
{
#if defined(TLSBM_ENV_DEBUG_ENABLE)
    wolfSSL_Debugging_ON();
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)

    wolfSSL_Init();
} // End: TLSBM_TlsLib_Startup()


//------------------------------------------------------------------------------
//
// Creates a security context. Returns security context handle.
//
//------------------------------------------------------------------------------
void* TLSBM_TlsLib_CreateSecurityContext(bool isServer,
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
        TLSBM_Common_Die("wolf method error");
    }

    WOLFSSL_CTX* pCtx = wolfSSL_CTX_new(pMethod);
    if (pCtx == NULL)
    {
        TLSBM_Common_Die("wolf ctx error");
    }
    if (isServer)
    {
        wolfSSL_CTX_set_psk_server_callback(pCtx, &tlsbm_TlsLib_ServerPskCb);
        wolfSSL_CTX_use_psk_identity_hint(pCtx, "");
    }
    else
    {
        wolfSSL_CTX_set_psk_client_callback(pCtx, &tlsbm_TlsLib_ClientPskCb);
    }

    if (wolfSSL_CTX_load_verify_locations(pCtx, pCaCertPath, 0) != WOLFSSL_SUCCESS)
    {
        TLSBM_Common_Die("invalid cert path");
    }

    if (pDevCertPath != NULL)
    {
        int format = devCertFileType == TLSLIB_FILE_TYPE_DER ? WOLFSSL_FILETYPE_ASN1 : WOLFSSL_FILETYPE_PEM;

        if (wolfSSL_CTX_use_certificate_file(pCtx,
                                             pDevCertPath,
                                             format) != WOLFSSL_SUCCESS)
        {
            printf("Device cert load error: %s", pDevCertPath);
            TLSBM_Common_Die("");
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
            TLSBM_Common_Die("");
        }
    }
    else
    {
        printf("Warning: Device key not set.");
    }

    if (!wolfSSL_CTX_set_cipher_list(pCtx, pCipherList))
    {
        TLSBM_Common_Die("wolf cipher list error");
    }

    return pCtx;
} // End: TLSBM_TlsLib_CreateSecurityContext()


//------------------------------------------------------------------------------
//
// Makes a sd secure. Returns secure sd context handle.
//
//--------------------------------------------------------------------------
void* TLSBM_TlsLib_MakeSocketSecure(int sd,
                                 void* pSecureCtx)
{
    WOLFSSL_CTX* pCtx = (WOLFSSL_CTX*)pSecureCtx;
    WOLFSSL* pSsl = wolfSSL_new(pCtx);
    if (pSsl == NULL)
    {
        TLSBM_Common_Die("wolfSSL_new error");
    }

    if (wolfSSL_set_fd(pSsl, sd) != WOLFSSL_SUCCESS)
    {
        TLSBM_Common_Die("wolfSSL_set_fd error");
    }

    return (void*)pSsl;
} // End: TLSBM_TlsLib_MakeSocketSecure()


//------------------------------------------------------------------------------
//
// Makes a sd secure. Returns secure sd context handle.
//
//--------------------------------------------------------------------------
void* TLSBM_TlsLib_MakeDtlsSocketSecure(int* pSd,
                                     void* pSecureCtx,
                                     void* pPeerAddr,
                                     size_t peerAddrSize)
{
    WOLFSSL_CTX* pCtx = (WOLFSSL_CTX*)pSecureCtx;
    WOLFSSL* pSsl = wolfSSL_new(pCtx);
    if (pSsl == NULL)
    {
        TLSBM_Common_Die("wolfSSL_new error");
    }

    if (wolfSSL_set_fd(pSsl, *pSd) != WOLFSSL_SUCCESS)
    {
        TLSBM_Common_Die("wolfSSL_set_fd error");
    }

    if (wolfSSL_dtls_set_peer(pSsl, pPeerAddr, peerAddrSize)!= WOLFSSL_SUCCESS)
    {
        TLSBM_Common_Die("wolf wolfSSL_dtls_set_peer error");
    }

    return (void*)pSsl;
} // End: TLSBM_TlsLib_MakeSocketSecure()


//------------------------------------------------------------------------------
//
// Unmakes security of a sd. Frees secure sd context per
// its handle.
//
//------------------------------------------------------------------------------
void TLSBM_TlsLib_UnmakeSocketSecure(int sd, void* pSecureSocketCtx)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;
    wolfSSL_shutdown(pSsl);
    wolfSSL_free(pSsl);
} // End: TLSBM_TlsLib_UnmakeSocketSecure()


//------------------------------------------------------------------------------
//
// Destroys a security context.
//
//------------------------------------------------------------------------------
void TLSBM_TlsLib_DestroySecureContext(void* pSecureCtx)
{
    WOLFSSL_CTX* pCtx = (WOLFSSL_CTX*)pSecureCtx;
    wolfSSL_CTX_free(pCtx);
} // End: TLSBM_TlsLib_DestroySecureContext()


//------------------------------------------------------------------------------
//
// Performs client handshake.
//
//------------------------------------------------------------------------------
void TLSBM_TlsLib_ClientHandshake(int sd, void* pSecureSocketCtx)
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
#if defined(TLSBM_ENV_DEBUG_ENABLE)
        printf("ssl connect error %d, %s\n", err,
            wolfSSL_ERR_error_string(err, tlsbm_TlsLib_errBuffer));
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
        TLSBM_Common_Die("ssl connect failed");
    }
} // End: TLSBM_TlsLib_ClientHandshake()


//------------------------------------------------------------------------------
//
// Performs server handshake.
//
//------------------------------------------------------------------------------
int TLSBM_TlsLib_ServerHandshake(int sd, void* pSecureSocketCtx)
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
#if defined(TLSBM_ENV_DEBUG_ENABLE)
        printf("wolf accept error = %d, %s\n", err,
               wolfSSL_ERR_error_string(err, tlsbm_TlsLib_errBuffer));
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
        wolfSSL_free(pSsl);
        ret = -1;
    }


    return (ret != WOLFSSL_SUCCESS) ? -1 : 0;
} // End: TLSBM_TlsLib_ServerHandshake()


//------------------------------------------------------------------------------
//
// Sends data securely until everything has been sent in a loop.
//
//------------------------------------------------------------------------------
void TLSBM_TlsLib_SendAll(int sd,
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
} // End: TLSBM_TlsLib_SendAll()


void TLSBM_TlsLib_SendToAll(int sd,
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
void TLSBM_TlsLib_SendOneByOneByte(int sd,
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
#if defined(TLSBM_ENV_DEBUG_ENABLE)
            printf("Sending %u / %zu: %c (%02x)\n",
                   offset+1,
                   dataBytes,
                   pData[offset],
                   pData[offset]);
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
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
} // End: TLSBM_TlsLib_SendOneByOneByte()


//------------------------------------------------------------------------------
//
// Sends data securely at once. No loop involved.
//
//------------------------------------------------------------------------------
void TLSBM_TlsLib_SendAllInOne(int sd,
                            void* pSecureSocketCtx,
                            uint8_t* pData,
                            size_t dataBytes)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSecureSocketCtx;

    int ret = wolfSSL_write(pSsl, pData, (int)dataBytes);
    if (ret != dataBytes)
    {
        int err = wolfSSL_get_error(pSsl, 0);
#if defined(TLSBM_ENV_DEBUG_ENABLE)
        printf("ssl write error %d, %s\n", err,
               wolfSSL_ERR_error_string(err, tlsbm_TlsLib_errBuffer));
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
        TLSBM_Common_Die("Wolfssl ERROR!");
    }
} // End: TLSBM_TlsLib_SendOneByOneByte()



//------------------------------------------------------------------------------
//
// reads data of specified length
//
//------------------------------------------------------------------------------
int TLSBM_TlsLib_Recv(int sd,
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
    } while (err == WC_PENDING_E);

    if (offset >= 0)
    {
        return offset;
    }

#if defined(TLSBM_ENV_DEBUG_ENABLE)
    printf("wolfSSL read error %d, %s!\n", err, wolfSSL_ERR_error_string(err, tlsbm_TlsLib_errBuffer));
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
    return -1;
}

static unsigned int tlsbm_TlsLib_ServerPskCb(WOLFSSL* pSsl,
                                          const char* pRecvdIdentity,
                                          unsigned char* pKey,
                                          unsigned int keyBytes)
{
    (void)pSsl;

    const char* pOurPskIdentity = TLSBM_Common_GetPskIdentity();
    size_t ourPskBytes = 0;
    uint8_t* pOurPsk = TLSBM_Common_GetPsk(&ourPskBytes);

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

static unsigned int tlsbm_TlsLib_ClientPskCb(WOLFSSL* pSsl,
                                          const char* pHint,
                                          char* pIdentity,
                                          unsigned int identityBytes,
                                          unsigned char* pKey,
                                          unsigned int keyBytes)
{
    (void)pSsl;
    (void)pHint;

    const char* pOurPskIdentity = TLSBM_Common_GetPskIdentity();
    size_t ourPskBytes = 0;
    uint8_t* pOurPsk = TLSBM_Common_GetPsk(&ourPskBytes);

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
void TLSBM_TlsLib_Shutdown(void)
{
    wolfSSL_Cleanup();
} // End: TLSBM_TlsLib_Shutdown()

void *XMALLOC(size_t n, void* heap, int type)
{
    (void)heap;
    (void)type;
    return TLSBM_Common_Malloc(n);
}

void *XREALLOC(void *p, size_t n, void* heap, int type)
{
    (void)heap;
    (void)type;
    return TLSBM_Common_Realloc(p,n);
}

void XFREE(void *p, void* heap, int type)
{
    (void)heap;
    (void)type;
    return TLSBM_Common_Free(p);
}

const char* TLSBM_TlsLib_GetName(void)
{
    return "wolfssl";
}
