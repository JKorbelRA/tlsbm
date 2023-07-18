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
                                      const char* pCipherList)
{
    WOLFSSL_METHOD* pMethod = NULL;
    if (isServer)
    {
        pMethod = wolfTLSv1_2_server_method();
    }
    else
    {
        pMethod = wolfTLSv1_2_client_method();
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

    if (wolfSSL_CTX_load_verify_locations(pCtx, pCaCertPath, 0) != WOLFSSL_SUCCESS)
    {
        CW_Common_Die("invalid cert path");
    }

    if (pDevCertPath != NULL)
    {
        int type = devCertFileType == TLSLIB_FILE_TYPE_DER ? WOLFSSL_FILETYPE_DER : WOLFSSL_FILETYPE_PEM;

        if (wolfSSL_CTX_use_certificate_file(pCtx,
                                             pDevCertPath,
                                             type) != WOLFSSL_SUCCESS)
        {
            CW_Common_Die("Device cert load error: %s", pDevCertPath);
        }
    }
    else
    {
        printf("Warning: Device certificate not set.");
    }

    if (pDevKeyPath != NULL)
    {
        type = devKeyFileType == TLSLIB_FILE_TYPE_DER ? WOLFSSL_FILETYPE_DER : WOLFSSL_FILETYPE_PEM;

        if (wolfSSL_CTX_use_PrivateKey_file(pCtx, pDevKeyPath, type) != WOLFSSL_SUCCESS)
        {
            CW_Common_Die("Device key load error: %s", pDevKeyPath);
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
void* CW_TlsLib_MakeSocketSecure(int sd, void* pSecureCtx)
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

    return (void*)pSsl;
} // End: CW_TlsLib_MakeSocketSecure()


//------------------------------------------------------------------------------
//
// Unmakes security of a sd. Frees secure sd context per
// its handle.
//
//------------------------------------------------------------------------------
void CW_TlsLib_UnmakeSocketSecure(int sd, void* pSocketSecureCtx)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSocketSecureCtx;
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
void CW_TlsLib_ClientHandshake(int sd, void* pSocketSecureCtx)
{
    (void)sd;
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
} // End: CW_TlsLib_ClientHandshake()


//------------------------------------------------------------------------------
//
// Performs server handshake.
//
//------------------------------------------------------------------------------
int CW_TlsLib_ServerHandshake(int sd, void* pSocketSecureCtx)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSocketSecureCtx;
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

    ret = 0;
    if (ret != WOLFSSL_SUCCESS)
    {
#if defined(CW_ENV_DEBUG_ENABLE)
        printf("wolf accept error = %d, %s\n", err,
               wolfSSL_ERR_error_string(err, cw_TlsLib_errBuffer));
#endif // defined(CW_ENV_DEBUG_ENABLE)
        wolfSSL_free(pSsl);
        CloseSocket(sd);
        ret = -1;
    }


    return ret;
} // End: CW_TlsLib_ServerHandshake()


//------------------------------------------------------------------------------
//
// Sends data securely until everything has been sent in a loop.
//
//------------------------------------------------------------------------------
void CW_TlsLib_SendAll(int sd,
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
} // End: CW_TlsLib_SendAll()


//------------------------------------------------------------------------------
//
// Sends data securely until everything has been sent in a loop but
// byte by byte.
//
//------------------------------------------------------------------------------
void CW_TlsLib_SendOneByOneByte(int sd,
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
} // End: CW_TlsLib_SendOneByOneByte()


//------------------------------------------------------------------------------
//
// Sends data securely at once. No loop involved.
//
//------------------------------------------------------------------------------
void CW_TlsLib_SendAllInOne(int sd,
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
                   void* pSocketSecureCtx,
                   uint8_t* pData,
                   size_t dataBytes)
{
    WOLFSSL* pSsl = (WOLFSSL*)pSocketSecureCtx;

    int offset = 0;
    int err = 0;

    // read while not [len] bytes read or some connection error
    do
    {
        err = 0;
        int ret = wolfSSL_read(pSsl, pData + offset, dataBytes - offset);
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



//-----------------------------------------------------------------------------
//
// Shut the security library down.
//
//-----------------------------------------------------------------------------
void CW_TlsLib_Shutdown(void)
{
    wolfSSL_Cleanup();
} // End: CW_TlsLib_Shutdown()
