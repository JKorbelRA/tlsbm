//==============================================================================
///
/// @file TlsLib.c
///
///
/// @brief A test TLS client using mbedTLS library.
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
#include <limits.h>
#include <string.h>


#include <tlsbm/Environment.h> // Generated header, look into CMake.

#include "../include/tlsbm/Common.h"
#include "../include/tlsbm/Platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "mbedtls/ssl_cookie.h"

//-----------------------------------------------------------------------------
// Constants
//-----------------------------------------------------------------------------

#define READ_TIMEOUT_MS 10000   /* 10 seconds */

//-----------------------------------------------------------------------------
// Macros
//-----------------------------------------------------------------------------



//-----------------------------------------------------------------------------
// Local data types
//-----------------------------------------------------------------------------

typedef struct
{
    mbedtls_ssl_config sslCfg;
    mbedtls_x509_crt caCert;
    mbedtls_x509_crt devCert;
    mbedtls_pk_context devKey;
    mbedtls_timing_delay_context timer;
    bool isServer;
    bool isTls;
    // DTLS
    mbedtls_ssl_cookie_ctx cookies;
} MbedTlsContext_t;

typedef struct
{
    mbedtls_ssl_context sslCtx;
    mbedtls_net_context netCtx;
    void* pPeerAddr;
    size_t peerAddrSize;
} MbedTlsObject_t;


//-----------------------------------------------------------------------------
// Local constants
//-----------------------------------------------------------------------------

#if defined(TLSBM_ENV_DEBUG_ENABLE)
/// @brief Error buffer for error texts.
static char tlsbm_TlsLib_errBuffer[16000] = {0};
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)


static void tlsbm_TlsLib_Debug(void* ctx, int level,
    const char* file, int line,
    const char* str);

mbedtls_entropy_context tlsbm_TlsLib_entropy;
mbedtls_ctr_drbg_context tlsbm_TlsLib_ctrDrbg;

int tlsbm_TlsLib_csLists[7][2] =
{
 {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 0},
 {MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, 0},
 {MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, 0},
 {MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, 0},
 {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
 {MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256, 0},
 {MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, 0}
};

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
    const char *pers = "ssl_server";

    mbedtls_ctr_drbg_init( &tlsbm_TlsLib_ctrDrbg );
    mbedtls_entropy_init( &tlsbm_TlsLib_entropy );
    if( mbedtls_ctr_drbg_seed( &tlsbm_TlsLib_ctrDrbg, mbedtls_entropy_func, &tlsbm_TlsLib_entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) )  != 0 )
    {
        TLSBM_Common_Die("mbedtls_ctr_drbg_seed error\n");
    }
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
    MbedTlsContext_t* pCtx = NULL;

    if (isTls)
    {
        pCtx = (MbedTlsContext_t*)TLSBM_Common_Malloc(sizeof(MbedTlsContext_t));
    }
    else
    {
        pCtx = (MbedTlsContext_t*)TLSBM_Common_Malloc(sizeof(MbedTlsContext_t));
    }

    if (pCtx == 0)
    {
        TLSBM_Common_Die("malloc cxt failed\n");
    }

    if (!isTls)
    {
        mbedtls_ssl_cookie_init(&pCtx->cookies);
    }


    mbedtls_x509_crt_init(&pCtx->caCert);
    int ret = mbedtls_x509_crt_parse_file(&pCtx->caCert, pCaCertPath);
    if (ret != 0) {
        TLSBM_Common_Die("mbedtls_x509_crt_parse_file ca\n");
    }

    mbedtls_x509_crt_init( &pCtx->devCert );
    ret = mbedtls_x509_crt_parse_file(&pCtx->devCert, pDevCertPath);
    if (ret != 0) {
        TLSBM_Common_Die("mbedtls_x509_crt_parse_file dc\n");
    }

    mbedtls_pk_init( &pCtx->devKey );
    ret =  mbedtls_pk_parse_keyfile(&pCtx->devKey,
                                    pDevKeyPath,
                                    NULL,
                                    mbedtls_ctr_drbg_random,
                                    &tlsbm_TlsLib_ctrDrbg);
    if (ret != 0) {
        TLSBM_Common_Die("mbedtls_pk_parse_keyfile error\n");
    }

    mbedtls_ssl_config_init( &pCtx->sslCfg );


    if (mbedtls_ssl_config_defaults(&pCtx->sslCfg,
                                    isServer ? MBEDTLS_SSL_IS_SERVER: MBEDTLS_SSL_IS_CLIENT,
                                    isTls ? MBEDTLS_SSL_TRANSPORT_STREAM : MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    {
        TLSBM_Common_Die("mbedtls_ssl_config_defaults error\n");
    }

    int* csPick = NULL;

    if (strcmp(pCipherList, TLSBM_CIPHER_SUITE_ECC_CERT) == 0)
    {
        csPick = &tlsbm_TlsLib_csLists[0][0];
    }
    else if (strcmp(pCipherList, TLSBM_CIPHER_SUITE_ECC_PSK) == 0)
    {
        csPick = &tlsbm_TlsLib_csLists[1][0];

    }
    else if (strcmp(pCipherList, TLSBM_CIPHER_SUITE_RSA_CERT) == 0)
    {
        csPick = &tlsbm_TlsLib_csLists[2][0];

    }
    else if (strcmp(pCipherList, TLSBM_CIPHER_SUITE_RSA_PSK) == 0)
    {
        csPick = &tlsbm_TlsLib_csLists[3][0];

    }
    else if (strcmp(pCipherList, TLSBM_CIPHER_SUITE_ECC_CERT_GCM) == 0)
    {
        csPick = &tlsbm_TlsLib_csLists[4][0];

    }
    else if (strcmp(pCipherList, TLSBM_CIPHER_SUITE_ECC_PSK_NULL) == 0)
    {
        csPick = &tlsbm_TlsLib_csLists[5][0];

    }
    else if (strcmp(pCipherList, TLSBM_CIPHER_SUITE_ECC_CHACHA20_POLY1305) == 0)
    {
        csPick = &tlsbm_TlsLib_csLists[6][0];

    }
    else
    {
        TLSBM_Common_Die("DYING: Unknown suite to mbedTLS.\n");
    }

    mbedtls_ssl_conf_ciphersuites(&pCtx->sslCfg, csPick);


    mbedtls_ssl_conf_rng(&pCtx->sslCfg, mbedtls_ctr_drbg_random, &tlsbm_TlsLib_ctrDrbg);
    mbedtls_ssl_conf_dbg(&pCtx->sslCfg, tlsbm_TlsLib_Debug, stdout);
#if defined(TLSBM_ENV_DEBUG_ENABLE)
    mbedtls_debug_set_threshold(4);
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)


    const char* pPskIdentity = TLSBM_Common_GetPskIdentity();
    size_t pskIdentitySize = strlen(pPskIdentity);
    size_t pskBytes = 0;
    uint8_t* pPsk = TLSBM_Common_GetPsk(&pskBytes);

    mbedtls_ssl_conf_psk(&pCtx->sslCfg, pPsk, pskBytes, (const uint8_t*)pPskIdentity, pskIdentitySize);
    mbedtls_ssl_conf_read_timeout(&pCtx->sslCfg, READ_TIMEOUT_MS);



    mbedtls_ssl_conf_ca_chain(&pCtx->sslCfg, &pCtx->caCert, NULL);
    if (mbedtls_ssl_conf_own_cert(&pCtx->sslCfg, &pCtx->devCert, &pCtx->devKey) != 0)
    {
        TLSBM_Common_Die("mbedtls_ssl_conf_own_cert error\n");
    }

    if (!isTls)
    {
        if (mbedtls_ssl_cookie_setup(&pCtx->cookies,
                                     mbedtls_ctr_drbg_random,
                                     &tlsbm_TlsLib_ctrDrbg) != 0)
        {
            TLSBM_Common_Die("mbedtls_ssl_conf_own_cert error\n");
        }

        mbedtls_ssl_conf_dtls_cookies(&pCtx->sslCfg,
                                      mbedtls_ssl_cookie_write,
                                      mbedtls_ssl_cookie_check,
                                      &pCtx->cookies);
    }

    pCtx->isServer = isServer;
    pCtx->isTls = isTls;

    return pCtx;
} // End: TLSBM_TlsLib_CreateSecurityContext()


static void tlsbm_TlsLib_Debug(void *ctx, int level,
                            const char *file, int line,
                            const char *str)
{
    (void) level;

    printf("%s:%04d: %s\n", file, line, str);
    fflush(stdout);
}

//------------------------------------------------------------------------------
//
// Makes a sd secure. Returns secure sd context handle.
//
//--------------------------------------------------------------------------
void* TLSBM_TlsLib_MakeSocketSecure(int sd,
                                 void* pSecureCtx)
{
    MbedTlsContext_t* pCtx = (MbedTlsContext_t*)pSecureCtx;

    MbedTlsObject_t* pSecureSocketContext = TLSBM_Common_Malloc(sizeof(MbedTlsObject_t));

    mbedtls_ssl_init(&pSecureSocketContext->sslCtx);

    if (mbedtls_ssl_setup(&pSecureSocketContext->sslCtx, &pCtx->sslCfg) != 0)
    {
        TLSBM_Common_Die("mbedtls_ssl_setup error\n");
    }

    mbedtls_ssl_set_timer_cb(&pSecureSocketContext->sslCtx,
                             &pCtx->timer,
                             mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    mbedtls_net_init(&pSecureSocketContext->netCtx);
    pSecureSocketContext->netCtx.fd = sd;
    mbedtls_ssl_set_bio(&pSecureSocketContext->sslCtx,
                        &pSecureSocketContext->netCtx,
                        mbedtls_net_send,
                        mbedtls_net_recv,
                        mbedtls_net_recv_timeout);

    return pSecureSocketContext;

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
    MbedTlsContext_t* pCtx = (MbedTlsContext_t*)pSecureCtx;

    MbedTlsObject_t* pSecureSocketContext = TLSBM_Common_Malloc(sizeof(MbedTlsObject_t));

    mbedtls_ssl_init(&pSecureSocketContext->sslCtx);

    if (mbedtls_ssl_setup(&pSecureSocketContext->sslCtx, &pCtx->sslCfg) != 0)
    {
        TLSBM_Common_Die("mbedtls_ssl_setup error\n");
    }

    mbedtls_ssl_set_timer_cb(&pSecureSocketContext->sslCtx,
                             &pCtx->timer,
                             mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    if (pCtx->isServer)
    {
        pSecureSocketContext->pPeerAddr = pPeerAddr;
        pSecureSocketContext->peerAddrSize = peerAddrSize;
    }

    mbedtls_net_init(&pSecureSocketContext->netCtx);

    uint32_t ip4Addr;
    uint16_t port;
    TLSBM_Common_GetIp4Port(&ip4Addr, &port);

    TLSBM_Platform_ConnectPa(*pSd, pPeerAddr, peerAddrSize);

    pSecureSocketContext->netCtx.fd = *pSd;
    mbedtls_ssl_set_bio(&pSecureSocketContext->sslCtx,
                        &pSecureSocketContext->netCtx,
                        mbedtls_net_send,
                        mbedtls_net_recv,
                        mbedtls_net_recv_timeout);
    *pSd = -1;

    return pSecureSocketContext;
} // End: TLSBM_TlsLib_MakeSocketSecure()


//------------------------------------------------------------------------------
//
// Unmakes security of a sd. Frees secure sd context per
// its handle.
//
//------------------------------------------------------------------------------
void TLSBM_TlsLib_UnmakeSocketSecure(int sd, void* pSecureSocketCtx)
{
    MbedTlsObject_t* pSsl = (MbedTlsObject_t*)pSecureSocketCtx;

    int ret = 0;
    /* No error checking, the connection might be closed already */
    do {
        ret = mbedtls_ssl_close_notify(&pSsl->sslCtx);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    mbedtls_net_free(&pSsl->netCtx);
    mbedtls_ssl_free(&pSsl->sslCtx);

    TLSBM_Common_Free(pSsl);

} // End: TLSBM_TlsLib_UnmakeSocketSecure()


//------------------------------------------------------------------------------
//
// Destroys a security context.
//
//------------------------------------------------------------------------------
void TLSBM_TlsLib_DestroySecureContext(void* pSecureCtx)
{
    MbedTlsContext_t* pCtx = (MbedTlsContext_t*)pSecureCtx;

    mbedtls_ssl_config_free(&pCtx->sslCfg);
    mbedtls_x509_crt_free(&pCtx->caCert);
    mbedtls_x509_crt_free(&pCtx->devCert);
    mbedtls_pk_free(&pCtx->devKey);

    if (!pCtx->isTls)
    {
        mbedtls_ssl_cookie_free(&pCtx->cookies);
    }

    TLSBM_Common_Free(pCtx);
} // End: TLSBM_TlsLib_DestroySecureContext()


//------------------------------------------------------------------------------
//
// Performs client handshake.
//
//------------------------------------------------------------------------------
void TLSBM_TlsLib_ClientHandshake(int sd, void* pSecureSocketCtx)
{
    MbedTlsObject_t* pSsl = (MbedTlsObject_t*)pSecureSocketCtx;

    int ret = 0;
    do
    {
        ret = mbedtls_ssl_handshake(&pSsl->sslCtx);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE);
} // End: TLSBM_TlsLib_ClientHandshake()


//------------------------------------------------------------------------------
//
// Performs server handshake.
//
//------------------------------------------------------------------------------
int TLSBM_TlsLib_ServerHandshake(int sd, void* pSecureSocketCtx)
{
    MbedTlsObject_t* pSsl = (MbedTlsObject_t*)pSecureSocketCtx;
    bool retry = true;
    int ret = 0;

    while(retry)
    {
        retry = false;
        if (mbedtls_ssl_set_client_transport_id(&pSsl->sslCtx,
                                                pSsl->pPeerAddr,
                                                pSsl->peerAddrSize) != 0)
        {
            TLSBM_Common_Die("mbedtls_ssl_set_client_transport_id error\n");
        }

        do
        {
            ret = mbedtls_ssl_handshake(&pSsl->sslCtx);
        } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)
        {
            mbedtls_ssl_session_reset(&pSsl->sslCtx);
            retry = true;
            printf("hello verification requested\n");
        }
        else if (ret != 0)
        {
            printf("ERROR mbedtls_ssl_handshake error\n");
        }
    }

    return ret;
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
    MbedTlsObject_t* pSsl = (MbedTlsObject_t*)pSecureSocketCtx;

    int ret = 0;
    do {
        ret = mbedtls_ssl_write(&pSsl->sslCtx, pData, dataBytes);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE);
} // End: TLSBM_TlsLib_SendAll()


void TLSBM_TlsLib_SendToAll(int sd,
                         void* pSecureSocketCtx,
                         uint32_t ip4Addr,
                         uint16_t port,
                         uint8_t* pData,
                         size_t dataBytes)
{
    MbedTlsObject_t* pSsl = (MbedTlsObject_t*)pSecureSocketCtx;

    int ret = 0;
    do {
        ret = mbedtls_ssl_write(&pSsl->sslCtx, pData, dataBytes);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE);
}



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
    MbedTlsObject_t* pSsl = (MbedTlsObject_t*)pSecureSocketCtx;

    int ret = 0;
    do
    {
        ret = mbedtls_ssl_read(&pSsl->sslCtx, pData, dataBytes);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret <= 0) {
        switch (ret) {
            case MBEDTLS_ERR_SSL_TIMEOUT:
                printf(" timeout\n\n");
                return ret;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                printf(" connection was closed gracefully\n");
                return 0;

            default:
                printf(" mbedtls_ssl_read returned -0x%x\n\n", (unsigned int) -ret);
                return ret;
        }
    }

    return ret;
}


//-----------------------------------------------------------------------------
//
// Shut the security library down.
//
//-----------------------------------------------------------------------------
void TLSBM_TlsLib_Shutdown(void)
{
    mbedtls_ctr_drbg_free(&tlsbm_TlsLib_ctrDrbg);
    mbedtls_entropy_free(&tlsbm_TlsLib_entropy);
} // End: TLSBM_TlsLib_Shutdown()

const char* TLSBM_TlsLib_GetName(void)
{
    return "mbedtls";
}
