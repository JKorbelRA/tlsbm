//==============================================================================
///
/// @file Server.c
///
///
/// @brief A test TLS server using wolfsSLL library.
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
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>


#include <tlsbm/Environment.h> // Generated header, look into CMake.
#include "include/tlsbm/Common.h"
#include "include/tlsbm/Platform.h"
#include "include/tlsbm/TlsLib.h"

//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Macros
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Local data types
//------------------------------------------------------------------------------

//--------------------------------------------------------------------------
// Local constants
//--------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Global references
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Forward function declarations
//------------------------------------------------------------------------------

static void tlsbm_Server_TlsServer(uint32_t ip4Addr,
                                uint16_t port,
                                SuiteCfg_t* pSc);
static void tlsbm_Server_DtlsServer(uint32_t ip4Addr,
                                 uint16_t port,
                                 SuiteCfg_t* pSc);

//------------------------------------------------------------------------------
// Variable definitions
//------------------------------------------------------------------------------

Msg_t tlsbm_Server_inMsg;
MsgDtls_t tlsbm_Server_inDtlsMsg;

//------------------------------------------------------------------------------
// Function definitions
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
///
///  @brief main client function, reads inputBuffer from stdin and send it to the SSL server
///
/// @param[in] port - comm port
/// @param[in] pCertDirPath - path to certificates
///
/// @return return 0 on success
///
//------------------------------------------------------------------------------
static void tlsbm_Server_TlsServer(uint32_t ip4Addr,
                                uint16_t port,
                                SuiteCfg_t* pSc)
{
    TLSBM_Common_AllocLogMarkerBegin("Context");

    uint8_t* pAllocaHint = TLSBM_Common_Allocacheck();


    printf("TLS: Picking %s isEcc == %d\n",
           pSc->pCipherSuite,
           pSc->isEcc);

    void* pSecurityCtx = NULL;

    if (pSc->isEcc)
    {
        // ECC
        pSecurityCtx = TLSBM_TlsLib_CreateSecurityContext(true,
                                                       TLSBM_CACERT_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVCERT_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVKEY_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       true);
    }
    else
    {
        // RSA
        pSecurityCtx = TLSBM_TlsLib_CreateSecurityContext(true,
                                                       TLSBM_CACERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVCERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVKEY_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       true);
    }

    int listenSd = TLSBM_Platform_Socket(true);
    if (listenSd == -1) //INVALID_SOCKET undef on Unix
    {
        TLSBM_Common_Die("can't create socket");
    }

    TLSBM_Platform_Bind(listenSd, ip4Addr, port);
    TLSBM_Platform_Listen(listenSd);

    while (true)
    {
#if defined(TLSBM_ENV_DEBUG_ENABLE)
        printf("Accepting new client\n");
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
        int sd = TLSBM_Platform_Accept(listenSd);

        if (sd < 0)
        {
            continue;
        }
        TLSBM_Common_AllocLogMarkerEnd("Context");
        TLSBM_Common_AllocLogMarkerBegin("Handshake");
        void* pSecureSocketCtx = TLSBM_TlsLib_MakeSocketSecure(sd,
                                                            pSecurityCtx);

        int res = TLSBM_TlsLib_ServerHandshake(sd, pSecureSocketCtx);
        if (res != 0)
        {
            TLSBM_Platform_CloseSocket(sd);
            continue;
        }


        TLSBM_Common_AllocLogMarkerEnd("Handshake");
        TLSBM_Common_AllocLogMarkerBegin("Message");
        while (res == 0)
        {
            uint16_t payloadBytesBe = 0;
            res = TLSBM_TlsLib_Recv(sd,
                                 pSecureSocketCtx,
                                 (uint8_t*)&payloadBytesBe,
                                 2);
            if (res == 2)
            {
                size_t payloadBytes = TLSBM_Platform_Ntohs(payloadBytesBe);
                res = TLSBM_TlsLib_Recv(sd,
                                     pSecureSocketCtx,
                                     (uint8_t*)&tlsbm_Server_inMsg.str.payload,
                                     payloadBytes);
                if (res == payloadBytes)
                {
                    printf("\nMsg size: %d\nMsg:\n%s\n",
                           (int)payloadBytes,
                           (const char*)tlsbm_Server_inMsg.str.payload);
                }
#if defined(TLSBM_ENV_DEBUG_ENABLE)
                else
                {
                    printf("Recv payload failure\n");
                }
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
            }
#if defined(TLSBM_ENV_DEBUG_ENABLE)
            else
            {
                printf("Recv hdr failure\n");
            }
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
        }

        TLSBM_Common_AllocLogMarkerEnd("Message");


        TLSBM_TlsLib_UnmakeSocketSecure(sd, pSecureSocketCtx);
        TLSBM_Platform_CloseSocket(sd);
        TLSBM_Platform_FlushStdout();

        break;
    }

    TLSBM_TlsLib_DestroySecureContext(pSecurityCtx);
    TLSBM_Platform_CloseSocket(listenSd);
    TLSBM_Common_Allocaprint(pAllocaHint);
} // End: tlsbm_Server_TlsServer()


//------------------------------------------------------------------------------
///
///  @brief main client function, reads inputBuffer from stdin and send it to the SSL server
///
/// @param[in] port - comm port
/// @param[in] pCertDirPath - path to certificates
///
/// @return return 0 on success
///
//------------------------------------------------------------------------------
static void tlsbm_Server_DtlsServer(uint32_t ip4Addr,
                                 uint16_t port,
                                 SuiteCfg_t* pSc)
{

    TLSBM_Common_AllocLogMarkerBegin("Context");
    uint8_t* pAllocaHint = TLSBM_Common_Allocacheck();


    printf("DTLS: Picking %s isEcc == %d\n",
           pSc->pCipherSuite,
           pSc->isEcc);

    void* pSecurityCtx = NULL;

    if (pSc->isEcc)
    {
        // ECC
        pSecurityCtx = TLSBM_TlsLib_CreateSecurityContext(true,
                                                       TLSBM_CACERT_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVCERT_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVKEY_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       false);
    }
    else
    {
        // RSA
        pSecurityCtx = TLSBM_TlsLib_CreateSecurityContext(true,
                                                       TLSBM_CACERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVCERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVKEY_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       false);
    }

    int listenSd = TLSBM_Platform_Socket(false);
    if (listenSd == -1) //INVALID_SOCKET undef on Unix
    {
        TLSBM_Common_Die("can't create socket");
    }

    TLSBM_Platform_Bind(listenSd, 0, port);
    size_t peerAddrSize = 0;
    void* pPeerAddr = TLSBM_Platform_CreatePeerAddr4(&peerAddrSize, 0, 0);

    while (true)
    {
        int peekBytes = TLSBM_Platform_RecvfromPeek(listenSd,
                                                 tlsbm_Server_inDtlsMsg.msg,
                                                 sizeof(tlsbm_Server_inDtlsMsg.msg),
                                                 pPeerAddr,
                                                 &peerAddrSize);
        if (peekBytes <= 0)
        {
            continue;
        }

        TLSBM_Common_AllocLogMarkerEnd("Context");
        TLSBM_Common_AllocLogMarkerBegin("Handshake");
        int clientSd = listenSd;
        void* pSecureSocketCtx = TLSBM_TlsLib_MakeDtlsSocketSecure(&clientSd,
                                                                pSecurityCtx,
                                                                pPeerAddr,
                                                                peerAddrSize);
        if (listenSd != clientSd)
        {
            // Weird accept way follows (mbedTLS):

            listenSd = TLSBM_Platform_Socket(false);
            if (listenSd == -1) //INVALID_SOCKET undef on Unix
            {
                TLSBM_Common_Die("can't create socket");
            }

            TLSBM_Platform_Bind(listenSd, 0, port);
        }

        int res = TLSBM_TlsLib_ServerHandshake(clientSd, pSecureSocketCtx);
        if (res != 0)
        {
            TLSBM_Platform_CloseSocket(clientSd);
            continue;
        }

        TLSBM_Common_AllocLogMarkerEnd("Handshake");
        TLSBM_Common_AllocLogMarkerBegin("Message");

        while (res == 0)
        {
            uint16_t payloadBytesBe = 0;
            res = TLSBM_TlsLib_Recv(clientSd,
                                 pSecureSocketCtx,
                                 (uint8_t*)&tlsbm_Server_inDtlsMsg.msg,
                                 sizeof(tlsbm_Server_inDtlsMsg.msg));
            if (res >= 2)
            {
                size_t payloadBytes = TLSBM_Platform_Ntohs(tlsbm_Server_inDtlsMsg.str.payloadBytesBe);
                if ((size_t)res == payloadBytes+2)
                {
                    printf("\nMsg size: %d\nMsg:\n%s\n",
                           (int)payloadBytes,
                           (const char*)tlsbm_Server_inDtlsMsg.str.payload);
                }
#if defined(TLSBM_ENV_DEBUG_ENABLE)
                else
                {
                    printf("Recv payload failure\n");
                }
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
            }
#if defined(TLSBM_ENV_DEBUG_ENABLE)
            else
            {
                printf("Recv hdr failure\n");
            }
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
        }

        TLSBM_Common_AllocLogMarkerEnd("Message");


        TLSBM_TlsLib_UnmakeSocketSecure(clientSd, pSecureSocketCtx);
        TLSBM_Platform_CloseSocket(clientSd);
        TLSBM_Platform_FlushStdout();

        break;
    }

    TLSBM_Platform_DeletePeerAddr4(pPeerAddr);
    TLSBM_TlsLib_DestroySecureContext(pSecurityCtx);
    TLSBM_Platform_CloseSocket(listenSd);
    TLSBM_Common_Allocaprint(pAllocaHint);
} // End: tlsbm_Server_DtlsServer()


//------------------------------------------------------------------------------
///
/// @brief Entry point for the simple TLS Server
///
//------------------------------------------------------------------------------
int main(int argc, char** argv)
{
    TLSBM_Platform_Startup();
    TLSBM_Common_Startup("server", TLSBM_TlsLib_GetName());
    TLSBM_TlsLib_Startup();

    uint16_t port = SIMPLE_SSL_PORT;
    char* pServerIp4;

    if (argc == 2)
    {
        // use argv[1] as server IP
        pServerIp4 = argv[1];
    }
    else
    {
        // tell user, server IP can be set
        printf("USAGE: <tlsbm-XX-server.exe> [server_ip]\n");
        exit(-1);
    }

    uint32_t ip4Addr = TLSBM_Platform_GetIp4Addr(pServerIp4);


    TLSBM_Common_SetIp4Port(ip4Addr, port);
    char testName[128];

    for (int id = 0; ;id++)
    {
        SuiteCfg_t* pSc = TLSBM_Common_GetSuiteCfg(id);
        if (pSc != NULL)
        {
            size_t wouldBeWritten = snprintf(testName, sizeof(testName),
                                             "Test: TLS %s",
                                             pSc->pCipherSuite);
            if (wouldBeWritten > sizeof(testName))
            {
                TLSBM_Common_Die("cannot write test marker");
            }

            TLSBM_Common_AllocLogMarkerBegin(testName);
            tlsbm_Server_TlsServer(ip4Addr, port, pSc);
            TLSBM_Common_AllocLogMarkerEnd(testName);
            TLSBM_Platform_Sleep(1);
        }
        else
        {
            break;
        }
    }

    for (int id = 0; ;id++)
    {
        SuiteCfg_t* pSc = TLSBM_Common_GetSuiteCfg(id);
        if (pSc != NULL)
        {
            size_t wouldBeWritten = snprintf(testName, sizeof(testName),
                                             "Test: DTLS %s",
                                             pSc->pCipherSuite);
            if (wouldBeWritten > sizeof(testName))
            {
                TLSBM_Common_Die("cannot write test marker");
            }

            TLSBM_Common_AllocLogMarkerBegin(testName);
            tlsbm_Server_DtlsServer(ip4Addr, port, pSc);
            TLSBM_Common_AllocLogMarkerEnd(testName);
            TLSBM_Platform_Sleep(1);
        }
        else
        {
            break;
        }
    }

    printf("FINISHED\n");

    TLSBM_TlsLib_Shutdown();
    TLSBM_Common_Shutdown();
    TLSBM_Platform_Shutdown();

    return 0;
} // End: main()
