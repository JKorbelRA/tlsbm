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
#include <string.h>
#include <malloc.h>


#include <crazywolf/Common.h>
#include <crazywolf/TlsLib.h>
#include <crazywolf/Environment.h> // Generated header, look into CMake.

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
} MbedTlsContext_t;

typedef struct
{

    mbedtls_ssl_config sslCfg;
    mbedtls_x509_crt caCert;
    mbedtls_x509_crt devCert;
    mbedtls_pk_context devKey;
    mbedtls_timing_delay_context timer;

    // DTLS
    mbedtls_ssl_cookie_ctx cookies;
} MbedDtlsContext_t;

typedef struct
{
    mbedtls_ssl_context sslCtx;
    mbedtls_net_context netCtx;
} MbedTlsObject_t;

typedef struct
{
    mbedtls_ssl_context sslCtx;
    mbedtls_net_context netCtx;
} MbedDtlsObject_t;


//-----------------------------------------------------------------------------
// Local constants
//-----------------------------------------------------------------------------

#if defined(CW_ENV_DEBUG_ENABLE)
/// @brief Error buffer for error texts.
static char cw_TlsLib_errBuffer[16000] = {0};
#endif // defined(CW_ENV_DEBUG_ENABLE)


static void cw_TlsLib_Debug(void* ctx, int level,
    const char* file, int line,
    const char* str);

mbedtls_entropy_context cw_TlsLib_entropy;
mbedtls_ctr_drbg_context cw_TlsLib_ctrDrbg;

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
    const char *pers = "ssl_server";

    mbedtls_ctr_drbg_init( &cw_TlsLib_ctrDrbg );
    mbedtls_entropy_init( &cw_TlsLib_entropy );
    if( mbedtls_ctr_drbg_seed( &cw_TlsLib_ctrDrbg, mbedtls_entropy_func, &cw_TlsLib_entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) )  != 0 )
    {
        CW_Common_Die("mbedtls_ctr_drbg_seed error\n");
    }
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
    MbedDtlsContext_t* pCtx = NULL;

    if (isTls)
    {
        pCtx = (MbedDtlsContext_t*)malloc(sizeof(MbedTlsContext_t));
    }
    else
    {
        pCtx = (MbedDtlsContext_t*)malloc(sizeof(MbedDtlsContext_t));
    }

    if (pCtx == 0)
    {
        CW_Common_Die("malloc cxt failed\n");
    }

    if (!isTls)
    {
        mbedtls_ssl_cookie_init(&pCtx->cookies);
    }


    mbedtls_x509_crt_init(&pCtx->caCert);
    int ret = mbedtls_x509_crt_parse_file(&pCtx->caCert, pCaCertPath);
    if (ret != 0) {
        CW_Common_Die("mbedtls_x509_crt_parse_file ca\n");
    }

    mbedtls_x509_crt_init( &pCtx->devCert );
    ret = mbedtls_x509_crt_parse_file(&pCtx->devCert, pDevCertPath);
    if (ret != 0) {
        CW_Common_Die("mbedtls_x509_crt_parse_file dc\n");
    }

    mbedtls_pk_init( &pCtx->devKey );
    ret =  mbedtls_pk_parse_keyfile(&pCtx->devKey,
                                    pDevKeyPath,
                                    NULL,
                                    mbedtls_ctr_drbg_random,
                                    &cw_TlsLib_ctrDrbg);
    if (ret != 0) {
        CW_Common_Die("mbedtls_pk_parse_keyfile error\n");
    }

    mbedtls_ssl_config_init( &pCtx->sslCfg );


    if (mbedtls_ssl_config_defaults(&pCtx->sslCfg,
                                    isServer ? MBEDTLS_SSL_IS_SERVER: MBEDTLS_SSL_IS_CLIENT,
                                    isTls ? MBEDTLS_SSL_TRANSPORT_STREAM : MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    {
        CW_Common_Die("mbedtls_ssl_config_defaults error\n");
    }


    mbedtls_ssl_conf_rng(&pCtx->sslCfg, mbedtls_ctr_drbg_random, &cw_TlsLib_ctrDrbg);
    mbedtls_ssl_conf_dbg(&pCtx->sslCfg, cw_TlsLib_Debug, stdout);
    mbedtls_ssl_conf_read_timeout(&pCtx->sslCfg, READ_TIMEOUT_MS);


    mbedtls_ssl_conf_ca_chain(&pCtx->sslCfg, pCtx->devCert.next, NULL);
    if (mbedtls_ssl_conf_own_cert(&pCtx->sslCfg, &pCtx->devCert, &pCtx->devKey) != 0)
    {
        CW_Common_Die("mbedtls_ssl_conf_own_cert error\n");
    }

    if (!isTls)
    {
        if (mbedtls_ssl_cookie_setup(&pCtx->cookies,
                                     mbedtls_ctr_drbg_random,
                                     &cw_TlsLib_ctrDrbg) != 0)
        {
            CW_Common_Die("mbedtls_ssl_conf_own_cert error\n");
        }

        mbedtls_ssl_conf_dtls_cookies(&pCtx->sslCfg,
                                      mbedtls_ssl_cookie_write,
                                      mbedtls_ssl_cookie_check,
                                      &pCtx->cookies);
    }

    return pCtx;
} // End: CW_TlsLib_CreateSecurityContext()


static void cw_TlsLib_Debug(void *ctx, int level,
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
void* CW_TlsLib_MakeSocketSecure(int sd,
                                 void* pSecureCtx)
{
    MbedDtlsContext_t* pCtx = (MbedDtlsContext_t*)pSecureCtx;

    MbedTlsObject_t* pSecureSocketContext = malloc(sizeof(MbedTlsObject_t));

    if (mbedtls_ssl_setup(&pSecureSocketContext->sslCtx, &pCtx->sslCfg) != 0)
    {
        CW_Common_Die("mbedtls_ssl_setup error\n");
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

} // End: CW_TlsLib_MakeSocketSecure()


//------------------------------------------------------------------------------
//
// Makes a sd secure. Returns secure sd context handle.
//
//--------------------------------------------------------------------------
void* CW_TlsLib_MakeDtlsSocketSecure(int sd,
                                     void* pSecureCtx,
                                     void* pPeerAddr,
                                     size_t peerAddrSize)
{
    MbedDtlsContext_t* pCtx = (MbedDtlsContext_t*)pSecureCtx;

    MbedDtlsObject_t* pSecureSocketContext = malloc(sizeof(MbedDtlsObject_t));

    if (mbedtls_ssl_setup(&pSecureSocketContext->sslCtx, &pCtx->sslCfg) != 0)
    {
        CW_Common_Die("mbedtls_ssl_setup error\n");
    }

    mbedtls_ssl_set_timer_cb(&pSecureSocketContext->sslCtx,
                             &pCtx->timer,
                             mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    if (mbedtls_ssl_set_client_transport_id(&pSecureSocketContext->sslCtx,
                                            pPeerAddr,
                                            peerAddrSize) != 0)
    {
        CW_Common_Die("mbedtls_ssl_set_client_transport_id error\n");
    }

    mbedtls_net_init(&pSecureSocketContext->netCtx);
    pSecureSocketContext->netCtx.fd = sd;
    mbedtls_ssl_set_bio(&pSecureSocketContext->sslCtx,
                        &pSecureSocketContext->netCtx,
                        mbedtls_net_send,
                        mbedtls_net_recv,
                        mbedtls_net_recv_timeout);

    return pSecureSocketContext;
} // End: CW_TlsLib_MakeSocketSecure()


//------------------------------------------------------------------------------
//
// Unmakes security of a sd. Frees secure sd context per
// its handle.
//
//------------------------------------------------------------------------------
void CW_TlsLib_UnmakeSocketSecure(int sd, void* pSecureSocketCtx)
{
    MbedDtlsObject_t* pSsl = (MbedDtlsObject_t*)pSecureSocketCtx;

    mbedtls_net_free(&pSsl->netCtx);
    mbedtls_ssl_free(&pSsl->sslCtx);
} // End: CW_TlsLib_UnmakeSocketSecure()


//------------------------------------------------------------------------------
//
// Destroys a security context.
//
//------------------------------------------------------------------------------
void CW_TlsLib_DestroySecureContext(void* pSecureCtx)
{
    MbedTlsContext_t* pCtx = (MbedTlsContext_t*)pSecureCtx;

    mbedtls_x509_crt_free(&pCtx->caCert);
    mbedtls_x509_crt_free(&pCtx->devCert);
    mbedtls_pk_free(&pCtx->devKey);
    mbedtls_ssl_config_free(&pCtx->sslCfg);

    free(pCtx);
} // End: CW_TlsLib_DestroySecureContext()


//------------------------------------------------------------------------------
//
// Performs client handshake.
//
//------------------------------------------------------------------------------
void CW_TlsLib_ClientHandshake(int sd, void* pSecureSocketCtx)
{
    MbedDtlsObject_t* pSsl = (MbedDtlsObject_t*)pSecureSocketCtx;

    int ret = 0;
    do
    {
        ret = mbedtls_ssl_handshake(&pSsl->sslCtx);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    uint32_t flags;
    /* In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
     * handshake would not succeed if the peer's cert is bad.  Even if we used
     * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&pSsl->sslCtx)) != 0)
    {
#if !defined(MBEDTLS_X509_REMOVE_INFO)
        char vrfy_buf[512];
#endif

        printf(" failed\n");

#if !defined(MBEDTLS_X509_REMOVE_INFO)
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        printf("%s\n", vrfy_buf);
#endif
    }
    else
    {
        printf(" ok\n");
    }
} // End: CW_TlsLib_ClientHandshake()


//------------------------------------------------------------------------------
//
// Performs server handshake.
//
//------------------------------------------------------------------------------
int CW_TlsLib_ServerHandshake(int sd, void* pSecureSocketCtx)
{
    MbedDtlsObject_t* pSsl = (MbedDtlsObject_t*)pSecureSocketCtx;

    int ret = 0;
    do
    {
        ret = mbedtls_ssl_handshake(&pSsl->sslCtx);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)
    {
        printf("ERROR hello verification requested\n");
    }
    else if (ret != 0)
    {
        printf("ERROR mbedtls_ssl_handshake error\n");
    }

    return ret;
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
    MbedTlsObject_t* pSsl = (MbedTlsObject_t*)pSecureSocketCtx;

    int ret = 0;
    do {
        ret = mbedtls_ssl_write(&pSsl->sslCtx, pData, dataBytes);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE);
} // End: CW_TlsLib_SendAll()


void CW_TlsLib_SendToAll(int sd,
                         void* pSecureSocketCtx,
                         uint32_t ip4Addr,
                         uint16_t port,
                         uint8_t* pData,
                         size_t dataBytes)
{
    MbedDtlsObject_t* pSsl = (MbedDtlsObject_t*)pSecureSocketCtx;

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
int CW_TlsLib_Recv(int sd,
                   void* pSecureSocketCtx,
                   uint8_t* pData,
                   size_t dataBytes)
{
    MbedDtlsObject_t* pSsl = (MbedDtlsObject_t*)pSecureSocketCtx;

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
void CW_TlsLib_Shutdown(void)
{
    mbedtls_ctr_drbg_free(&cw_TlsLib_ctrDrbg);
    mbedtls_entropy_free(&cw_TlsLib_entropy);
} // End: CW_TlsLib_Shutdown()
