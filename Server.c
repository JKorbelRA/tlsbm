//==============================================================================
///
/// @file Server.c
///
///
/// @brief A test TLS server using wolfsSLL library.
///
/// Copyright (c) 2023 Rockwell Automation Technologies, Inc.
/// All rights reserved.
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


#include <crazywolf/Common.h>
#include <crazywolf/TlsLib.h>
#include <crazywolf/Platform.h>
#include <crazywolf/Environment.h> // Generated header, look into CMake.

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

static void cw_Server_TlsServer(uint32_t ip4Addr,
                                uint16_t port,
                                bool isPsk,
                                bool isRsa,
                                bool isGcm);
static void cw_Server_DtlsServer(uint32_t ip4Addr,
                                 uint16_t port,
                                 bool isPsk,
                                 bool isRsa,
                                 bool isGcm);

//------------------------------------------------------------------------------
// Variable definitions
//------------------------------------------------------------------------------

Msg_t cw_Server_inMsg;

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
static void cw_Server_TlsServer(uint32_t ip4Addr,
                                uint16_t port,
                                bool isRsa,
                                bool isPsk,
                                bool isGcm)
{
    CW_Common_AllocLogMarkerBegin("Context");

    uint8_t* pAllocaHint = CW_Common_Allocacheck();


    SuiteCfg_t* pCfg = CW_Common_GetCipherSuiteAndFiles(isPsk,
                                                        isRsa,
                                                        isGcm);
    printf("Picking %s %s %s %s\n",
           pCfg->pCipherSuite,
           pCfg->pCaCert,
           pCfg->pDevCert,
           pCfg->pDevKey);

    void* pSecurityCtx = CW_TlsLib_CreateSecurityContext(true,
                                                         pCfg->pCaCert,
                                                         TLSLIB_FILE_TYPE_PEM,
                                                         pCfg->pDevCert,
                                                         TLSLIB_FILE_TYPE_PEM,
                                                         pCfg->pDevKey,
                                                         TLSLIB_FILE_TYPE_DER,
                                                         pCfg->pCipherSuite,
                                                         true);

    int listenSd = CW_Platform_Socket(true);
    if (listenSd == -1) //INVALID_SOCKET undef on Unix
    {
        CW_Common_Die("can't create socket");
    }

    CW_Platform_Bind(listenSd, ip4Addr, port);
    CW_Platform_Listen(listenSd);

    while (true)
    {
        printf("Accepting new client\n");
        int sd = CW_Platform_Accept(listenSd);

        if (sd < 0)
        {
            continue;
        }
        CW_Common_AllocLogMarkerEnd("Context");
        CW_Common_AllocLogMarkerBegin("Handshake");
        void* pSecureSocketCtx = CW_TlsLib_MakeSocketSecure(sd,
                                                            pSecurityCtx);

        int res = CW_TlsLib_ServerHandshake(sd, pSecureSocketCtx);
        if (res != 0)
        {
            CW_Platform_CloseSocket(sd);
            continue;
        }


        CW_Common_AllocLogMarkerEnd("Handshake");
        CW_Common_AllocLogMarkerBegin("Message");
        while (res == 0)
        {
            uint16_t payloadBytesBe = 0;
            res = CW_TlsLib_Recv(sd,
                                 pSecureSocketCtx,
                                 (uint8_t*)&payloadBytesBe,
                                 2);
            if (res == 2)
            {
                size_t payloadBytes = CW_Platform_Ntohs(payloadBytesBe);
                res = CW_TlsLib_Recv(sd,
                                     pSecureSocketCtx,
                                     (uint8_t*)&cw_Server_inMsg.str.payload,
                                     payloadBytes);
                if (res == payloadBytes)
                {
                    printf("\nMsg size: %d\nMsg:\n%s\n",
                           (int)payloadBytes,
                           (const char*)cw_Server_inMsg.str.payload);
                }
                else
                {
                    printf("Recv payload failure\n");
                }
            }
            else
            {
                printf("Recv hdr failure\n");
            }
        }

        CW_Common_AllocLogMarkerEnd("Message");


        CW_TlsLib_UnmakeSocketSecure(sd, pSecureSocketCtx);
        CW_Platform_CloseSocket(sd);
        CW_Platform_FlushStdout();

        break;
    }

    CW_TlsLib_DestroySecureContext(pSecurityCtx);
    CW_Platform_CloseSocket(listenSd);
    CW_Common_Allocaprint(pAllocaHint);
} // End: cw_Server_TlsServer()


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
static void cw_Server_DtlsServer(uint32_t ip4Addr,
                                 uint16_t port,
                                 bool isRsa,
                                 bool isPsk,
                                 bool isGcm)
{

    CW_Common_AllocLogMarkerBegin("Context");
    uint8_t* pAllocaHint = CW_Common_Allocacheck();


    SuiteCfg_t* pCfg = CW_Common_GetCipherSuiteAndFiles(isPsk,
                                                        isRsa,
                                                        isGcm);
    printf("Picking %s %s %s %s\n",
           pCfg->pCipherSuite,
           pCfg->pCaCert,
           pCfg->pDevCert,
           pCfg->pDevKey);

    void* pSecurityCtx = CW_TlsLib_CreateSecurityContext(true,
                                                         pCfg->pCaCert,
                                                         TLSLIB_FILE_TYPE_PEM,
                                                         pCfg->pDevCert,
                                                         TLSLIB_FILE_TYPE_PEM,
                                                         pCfg->pDevKey,
                                                         TLSLIB_FILE_TYPE_DER,
                                                         pCfg->pCipherSuite,
                                                         false);

    int listenSd = CW_Platform_Socket(false);
    if (listenSd == -1) //INVALID_SOCKET undef on Unix
    {
        CW_Common_Die("can't create socket");
    }

    CW_Platform_Bind(listenSd, 0, port);
    size_t peerAddrSize = 0;
    void* pPeerAddr = CW_Platform_CreatePeerAddr4(&peerAddrSize, 0, 0);

    while (true)
    {
        int peekBytes = CW_Platform_RecvfromPeek(listenSd,
                                                 cw_Server_inMsg.msg,
                                                 sizeof(cw_Server_inMsg.msg),
                                                 pPeerAddr,
                                                 &peerAddrSize);
        if (peekBytes <= 0)
        {
            continue;
        }

        CW_Common_AllocLogMarkerEnd("Context");
        CW_Common_AllocLogMarkerBegin("Handshake");
        int clientSd = listenSd;
        void* pSecureSocketCtx = CW_TlsLib_MakeDtlsSocketSecure(&clientSd,
                                                                pSecurityCtx,
                                                                pPeerAddr,
                                                                peerAddrSize);
        if (listenSd != clientSd)
        {
            // Weird accept way follows (mbedTLS):

            listenSd = CW_Platform_Socket(false);
            if (listenSd == -1) //INVALID_SOCKET undef on Unix
            {
                CW_Common_Die("can't create socket");
            }

            CW_Platform_Bind(listenSd, 0, port);
        }

        int res = CW_TlsLib_ServerHandshake(clientSd, pSecureSocketCtx);
        if (res != 0)
        {
            CW_Platform_CloseSocket(clientSd);
            continue;
        }

        CW_Common_AllocLogMarkerEnd("Handshake");
        CW_Common_AllocLogMarkerBegin("Message");

        while (res == 0)
        {
            uint16_t payloadBytesBe = 0;
            res = CW_TlsLib_Recv(clientSd,
                                 pSecureSocketCtx,
                                 (uint8_t*)&cw_Server_inMsg.msg,
                                 sizeof(cw_Server_inMsg.msg));
            if (res >= 2)
            {
                size_t payloadBytes = CW_Platform_Ntohs(cw_Server_inMsg.str.payloadBytesBe);
                if ((size_t)res == payloadBytes+2)
                {
                    printf("\nMsg size: %d\nMsg:\n%s\n",
                           (int)payloadBytes,
                           (const char*)cw_Server_inMsg.str.payload);
                }
                else
                {
                    printf("Recv payload failure\n");
                }
            }
            else
            {
                printf("Recv hdr failure\n");
            }
        }

        CW_Common_AllocLogMarkerEnd("Message");


        CW_TlsLib_UnmakeSocketSecure(clientSd, pSecureSocketCtx);
        CW_Platform_CloseSocket(clientSd);
        CW_Platform_FlushStdout();

        break;
    }

    CW_Platform_DeletePeerAddr4(pPeerAddr);
    CW_TlsLib_DestroySecureContext(pSecurityCtx);
    CW_Platform_CloseSocket(listenSd);
    CW_Common_Allocaprint(pAllocaHint);
} // End: cw_Server_DtlsServer()


//------------------------------------------------------------------------------
///
/// @brief Entry point for the simple TLS Server
///
//------------------------------------------------------------------------------
int main(int argc, char** argv)
{
    CW_Platform_Startup();
    CW_Common_Startup("server", CW_TlsLib_GetName());
    CW_TlsLib_Startup();

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
        printf("USAGE: <crazywolf-XX-server.exe> [server_ip]\n");
        exit(-1);
    }

    uint32_t ip4Addr = CW_Platform_GetIp4Addr(pServerIp4);


    CW_Common_SetIp4Port(ip4Addr, port);


    printf("Starting TLS server, no PSK, ECC\n");
    CW_Common_AllocLogMarkerBegin("Test: TLS + CERT + ECC");
    cw_Server_TlsServer(ip4Addr, port, false, false, false);
    CW_Common_AllocLogMarkerEnd("Test: TLS + CERT + ECC");

    printf("Starting TLS server + PSK + ECC\n");
    CW_Common_AllocLogMarkerBegin("Test: TLS + PSK + ECC");
    cw_Server_TlsServer(ip4Addr, port, false, true, false);
    CW_Common_AllocLogMarkerEnd("Test: TLS + PSK + ECC");

    printf("Starting TLS server, no PSK, RSA\n");
    CW_Common_AllocLogMarkerBegin("Test: TLS + CERT + RSA");
    cw_Server_TlsServer(ip4Addr, port, true, false, false);
    CW_Common_AllocLogMarkerEnd("Test: TLS + CERT + RSA");

    printf("Starting TLS server + PSK + DHE\n");
    CW_Common_AllocLogMarkerBegin("Test: TLS + PSK + DHE");
    cw_Server_TlsServer(ip4Addr, port, true, true, false);
    CW_Common_AllocLogMarkerEnd("Test: TLS + PSK + DHE");

    printf("Starting TLS server, no PSK, ECC + GCM\n");
    CW_Common_AllocLogMarkerBegin("Test: TLS + CERT + ECC + GCM");
    cw_Server_TlsServer(ip4Addr, port, false, false, true);
    CW_Common_AllocLogMarkerEnd("Test: TLS + CERT + ECC + GCM");

    printf("Starting DTLS server, no PSK, ECC\n");
    CW_Common_AllocLogMarkerBegin("Test: DTLS + CERT + ECC");
    cw_Server_DtlsServer(ip4Addr, port, false, false, false);
    CW_Common_AllocLogMarkerEnd("Test: DTLS + CERT + ECC");

    printf("Starting DTLS server + PSK + ECC\n");
    CW_Common_AllocLogMarkerBegin("Test: DTLS + PSK + ECC");
    cw_Server_DtlsServer(ip4Addr, port, false, true, false);
    CW_Common_AllocLogMarkerEnd("Test: DTLS + PSK + ECC");

    printf("Starting DTLS server, no PSK, RSA\n");
    CW_Common_AllocLogMarkerBegin("Test: DTLS + CERT + RSA");
    cw_Server_DtlsServer(ip4Addr, port, true, false, false);
    CW_Common_AllocLogMarkerEnd("Test: DTLS + CERT + RSA");

    printf("Starting DTLS server + PSK + DHE\n");
    CW_Common_AllocLogMarkerBegin("Test: DTLS + PSK + DHE");
    cw_Server_DtlsServer(ip4Addr, port, true, true, false);
    CW_Common_AllocLogMarkerEnd("Test: DTLS + PSK + DHE");

    printf("Starting DTLS server, no PSK, ECC + GCM\n");
    CW_Common_AllocLogMarkerBegin("Test: DTLS + CERT + ECC + GCM");
    cw_Server_DtlsServer(ip4Addr, port, false, false, true);
    CW_Common_AllocLogMarkerEnd("Test: DTLS + CERT + ECC + GCM");


    CW_TlsLib_Shutdown();
    CW_Common_Shutdown();
    CW_Platform_Shutdown();

    return 0;
} // End: main()
