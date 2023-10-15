//==============================================================================
///
/// @file Client.c
///
///
/// @brief A test TLS client using several TLS libraries.
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
#include <stdbool.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>


#include <tlsbm/Environment.h> // Generated header, look into CMake.
#include "include/tlsbm/Common.h"
#include "include/tlsbm/Platform.h"
#include "include/tlsbm/TlsLib.h"


//-----------------------------------------------------------------------------
// Constants
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Macros
//-----------------------------------------------------------------------------



#define TLSBM_CLIENT_FLAG_NO_BASIC 0x01
#define TLSBM_CLIENT_FLAG_NO_1BY1 0x02
#define TLSBM_CLIENT_FLAG_NO_ATONCE 0x04

#define TLSBM_CLIENT_TESTSTR(payload, flags)\
        tlsbm_Client_SendTestMsg(sd, pSecureSocketCtx, payload, sizeof(payload) - 1, flags)
#define TLSBM_CLIENT_TESTMSG(payloadBytes, payload, flags)\
        tlsbm_Client_SendTestMsg(sd, pSecureSocketCtx, payload, payloadBytes, flags)


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


static void tlsbm_Client_TlsClient(uint32_t ip4Addr,
                                uint16_t port,
                                SuiteCfg_t* pSc);

static void tlsbm_Client_DtlsClient(uint32_t ip4Addr,
                                 uint16_t port,
                                 SuiteCfg_t* pSc);

//-----------------------------------------------------------------------------
// Variable definitions
//-----------------------------------------------------------------------------


static Msg_t tlsbm_Client_msg;

static MsgDtls_t tlsbm_Client_dtlsMsg;

//-----------------------------------------------------------------------------
// Function definitions
//-----------------------------------------------------------------------------


static void tlsbm_Client_SendTestMsg(int sd,
                                  void* pSecureSocketCtx,
                                  uint8_t* pData,
                                  size_t dataBytes)
{
    tlsbm_Client_msg.str.payloadBytesBe = TLSBM_Platform_Htons((uint16_t)dataBytes);
    tlsbm_Client_msg.str.zero = 0;
    memcpy(tlsbm_Client_msg.str.payload, pData, dataBytes);

    printf("Testing following message (%u bytes):\n%s\n",
           (unsigned int)dataBytes,
           pData);

    TLSBM_TlsLib_SendAll(sd,
                      pSecureSocketCtx,
                      tlsbm_Client_msg.msg,
                      dataBytes+2);
}


static void tlsbm_Client_SendToTestMsg(int sd,
                                    void* pSecureSocketCtx,
                                    uint32_t serverIp4,
                                    uint16_t port,
                                    uint8_t* pData,
                                    size_t dataBytes)
{
    tlsbm_Client_dtlsMsg.str.payloadBytesBe = TLSBM_Platform_Htons((uint16_t)dataBytes);
    tlsbm_Client_dtlsMsg.str.zero = 0;
    memcpy(tlsbm_Client_dtlsMsg.str.payload, pData, dataBytes);

    printf("Testing following message (%u bytes):\n%s\n",
           (unsigned int)dataBytes,
           pData);

    TLSBM_TlsLib_SendToAll(sd,
                        pSecureSocketCtx,
                        serverIp4,
                        port,
                        tlsbm_Client_dtlsMsg.msg,
                        dataBytes+2);
}

//-----------------------------------------------------------------------------
///
/// @brief main client function, reads inputBuffer from stdin and send it to the SSL server
///
/// @param[in] pServerIp4 - server IP
/// @param[in] port - comm port
/// @param[in] pCertDirPath - path to certificates
/// @return 0 on success
///
//-----------------------------------------------------------------------------
static void tlsbm_Client_TlsClient(uint32_t ip4Addr,
                                uint16_t port,
                                SuiteCfg_t* pSc)
{
    TLSBM_Common_AllocLogMarkerBegin("Context");
    uint8_t* pAllocaHint = TLSBM_Common_Allocacheck();
#if defined(TLSBM_ENV_DEBUG_ENABLE)
    printf("Connecting server\n");
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)

    int sd = TLSBM_Platform_Socket(true);

    if (sd == -1) // INVALID_SOCKET undef in Unix
    {
        TLSBM_Common_Die("can't get sd");
    }

    if (TLSBM_Platform_Connect(sd, ip4Addr, port) == -1)
    {
        TLSBM_Common_Die("sd connect failed");
    }

#if defined(TLSBM_ENV_DEBUG_ENABLE)
    printf("Server %d:%d connected\n", ip4Addr, port);
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)


    printf("TLS: Picking %s isEcc == %d\n",
           pSc->pCipherSuite,
           pSc->isEcc);

    void* pSecurityCtx = NULL;

    if (pSc->isEcc)
    {
        // ECC
        pSecurityCtx = TLSBM_TlsLib_CreateSecurityContext(false,
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
        pSecurityCtx = TLSBM_TlsLib_CreateSecurityContext(false,
                                                       TLSBM_CACERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVCERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVKEY_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       true);
    }
    TLSBM_Common_AllocLogMarkerEnd("Context");
    TLSBM_Common_AllocLogMarkerBegin("Handshake");

    void* pSecureSocketCtx = TLSBM_TlsLib_MakeSocketSecure(sd, pSecurityCtx);

    TLSBM_TlsLib_ClientHandshake(sd, pSecureSocketCtx);
    TLSBM_Common_AllocLogMarkerEnd("Handshake");
    TLSBM_Common_AllocLogMarkerBegin("Message");


    // Let's test!
#if defined(TLSBM_ENV_DEBUG_ENABLE)
    printf("Hello world test\n");
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
    tlsbm_Client_SendTestMsg(sd,
                          pSecureSocketCtx,
                          "Hello world",
                          sizeof("Hello world")-1);
    TLSBM_Common_AllocLogMarkerEnd("Message");

    TLSBM_TlsLib_UnmakeSocketSecure(sd, pSecureSocketCtx);
    TLSBM_Platform_CloseSocket(sd);
    TLSBM_TlsLib_DestroySecureContext(pSecurityCtx);


    TLSBM_Common_Allocaprint(pAllocaHint);
    TLSBM_Platform_FlushStdout();
} // End: tlsbm_Client_TlsClient()


//-----------------------------------------------------------------------------
///
/// @brief main client function, reads inputBuffer from stdin and send it to the SSL server
///
/// @param[in] pServerIp4 - server IP
/// @param[in] port - comm port
/// @param[in] pCertDirPath - path to certificates
/// @return 0 on success
///
//-----------------------------------------------------------------------------
static void tlsbm_Client_DtlsClient(uint32_t ip4Addr,
                                 uint16_t port,
                                 SuiteCfg_t* pSc)
{
    TLSBM_Common_AllocLogMarkerBegin("Context");

    uint8_t* pAllocaHint = TLSBM_Common_Allocacheck();

    int sd = TLSBM_Platform_Socket(false);

    if (sd == -1) // INVALID_SOCKET undef in Unix
    {
        TLSBM_Common_Die("can't get sd");
    }

    printf("DTLS: Picking %s isEcc == %d\n",
           pSc->pCipherSuite,
           pSc->isEcc);

    void* pSecurityCtx = NULL;

    if (pSc->isEcc)
    {
        // ECC
        pSecurityCtx = TLSBM_TlsLib_CreateSecurityContext(false,
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
        pSecurityCtx = TLSBM_TlsLib_CreateSecurityContext(false,
                                                       TLSBM_CACERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVCERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       TLSBM_DEVKEY_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       false);
    }

    TLSBM_Common_AllocLogMarkerEnd("Context");
    TLSBM_Common_AllocLogMarkerBegin("Handshake");

    size_t peerAddrSize = 0;
    void* pPeerAddr = TLSBM_Platform_CreatePeerAddr4(&peerAddrSize, ip4Addr, port);
    void* pSecureSocketCtx = TLSBM_TlsLib_MakeDtlsSocketSecure(&sd,
                                                            pSecurityCtx,
                                                            pPeerAddr,
                                                            peerAddrSize);

    TLSBM_TlsLib_ClientHandshake(sd, pSecureSocketCtx);

    TLSBM_Common_AllocLogMarkerEnd("Handshake");
    TLSBM_Common_AllocLogMarkerBegin("Message");

    // Let's test!
#if defined(TLSBM_ENV_DEBUG_ENABLE)
    printf("Hello world test\n");
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)
    tlsbm_Client_SendToTestMsg(sd,
                            pSecureSocketCtx,
                            ip4Addr,
                            port,
                            "Hello world",
                            sizeof("Hello world")-1);

    TLSBM_Common_AllocLogMarkerEnd("Message");

    TLSBM_TlsLib_UnmakeSocketSecure(sd, pSecureSocketCtx);
    TLSBM_Platform_CloseSocket(sd);
    TLSBM_TlsLib_DestroySecureContext(pSecurityCtx);
    TLSBM_Platform_DeletePeerAddr4(pPeerAddr);


    TLSBM_Common_Allocaprint(pAllocaHint);
    TLSBM_Platform_FlushStdout();
} // End: tlsbm_Client_DtlsClient()


//------------------------------------------------------------------------------
///
/// @brief Entry point for the simple TLS Client
///
//------------------------------------------------------------------------------
int main(int argc, char** argv)
{
    TLSBM_Platform_Startup();
    TLSBM_Common_Startup("client", TLSBM_TlsLib_GetName());
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
        printf("USAGE: <tlsbm-XX-client.exe> [server_ip]\n");
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
            tlsbm_Client_TlsClient(ip4Addr, port, pSc);
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
            tlsbm_Client_DtlsClient(ip4Addr, port, pSc);
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


#if 0
TLSBM_CLIENT_TESTSTR("Hello", 0);
TLSBM_CLIENT_TESTSTR("Testing Testing", 0);


printf("Test case 1: Smallest message\n");
TLSBM_CLIENT_TESTSTR("", 0);

printf("Test case 2: Largest message\n");
tlsbm_Client_msg.str.payloadBytesBe = UINT16_MAX;
for (uint16_t i = 0; i < UINT16_MAX; i++)
{
    tlsbm_Client_msg.str.payload[i] = 'a';
}
for (uint32_t i = 0; i < UINT16_MAX+2; i++)
{
    printf("%c\n", tlsbm_Client_msg.msg[i]);
}

printf("\t HAPPY\n");
TLSBM_TlsLib_SendAll(sd,
                  pSecurityCtx,
                  tlsbm_Client_msg.str.payload,
                  TLSBM_Platform_Ntohs(tlsbm_Client_msg.str.payloadBytesBe));
printf("\t one-by-one\n");
TLSBM_TlsLib_SendOneByOneByte(sd,
                           pSecurityCtx,
                           tlsbm_Client_msg.str.payload,
                           TLSBM_Platform_Ntohs(tlsbm_Client_msg.str.payloadBytesBe));
printf("\t at once!\n");
TLSBM_TlsLib_SendAllInOne(sd,
                       pSecurityCtx,
                       tlsbm_Client_msg.str.payload,
                       TLSBM_Platform_Ntohs(tlsbm_Client_msg.str.payloadBytesBe));
printf("\t DONE!\n");

printf("Test case 3: Zeroes and newlines\n");
tlsbm_Client_msg.str.payloadBytesBe = TLSBM_Platform_Htons(4);
tlsbm_Client_msg.str.payload[0] = '0';
tlsbm_Client_msg.str.payload[1] = '\0';
tlsbm_Client_msg.str.payload[2] = 'n';
tlsbm_Client_msg.str.payload[3] = '\n';

printf("\t HAPPY\n");
TLSBM_TlsLib_SendAll(sd,
                  pSecurityCtx,
                  tlsbm_Client_msg.str.payload,
                  TLSBM_Platform_Ntohs(tlsbm_Client_msg.str.payloadBytesBe));
printf("\t one-by-one\n");
TLSBM_TlsLib_SendOneByOneByte(sd,
                           pSecurityCtx,
                           tlsbm_Client_msg.str.payload,
                           TLSBM_Platform_Ntohs(tlsbm_Client_msg.str.payloadBytesBe));
printf("\t at once!\n");
TLSBM_TlsLib_SendAllInOne(sd,
                       pSecurityCtx,
                       tlsbm_Client_msg.str.payload,
                       TLSBM_Platform_Ntohs(tlsbm_Client_msg.str.payloadBytesBe));
printf("\t DONE!\n");


static void tlsbm_Client_SendTestMsg(int sd,
                                  void* pSecureSocketCtx,
                                  uint8_t* pData,
                                  size_t dataBytes,
                                  uint8_t flags)
{
    tlsbm_Client_msg.str.payloadBytesBe = TLSBM_Platform_Htons((uint16_t)dataBytes);
    tlsbm_Client_msg.str.zero = 0;
    memcpy(tlsbm_Client_msg.str.payload, pData, dataBytes);

    printf("Testing following message (%u bytes):\n%s\n",
           (unsigned int)dataBytes,
           pData);

    if ((flags & TLSBM_CLIENT_FLAG_NO_BASIC) == 0)
    {
        printf("Basic test running.\n");
        TLSBM_TlsLib_SendAll(sd,
                          pSecureSocketCtx,
                          tlsbm_Client_msg.msg,
                          dataBytes+2);
        printf("Basic test DONE.\n");
    }
    else
    {
        printf("Basic test disabled.\n");
    }

    if ((flags & TLSBM_CLIENT_FLAG_NO_1BY1) == 0)
    {
        printf("1-by-1 test running.\n");
        TLSBM_TlsLib_SendOneByOneByte(sd,
                                   pSecureSocketCtx,
                                   tlsbm_Client_msg.msg,
                                   dataBytes+2);
        printf("1-by-1 test DONE.\n");
    }
    else
    {
        printf("1-by-1 test disabled.\n");
    }

    if ((flags & TLSBM_CLIENT_FLAG_NO_ATONCE) == 0)
    {
        printf("All-at-once test running.\n");
        TLSBM_TlsLib_SendAllInOne(sd,
                               pSecureSocketCtx,
                               tlsbm_Client_msg.msg,
                               dataBytes+2);
        printf("All-at-once test DONE.\n");
    }
    else
    {
        printf("All-at-once test disabled.\n");
    }
}
#endif
