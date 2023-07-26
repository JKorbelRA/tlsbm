//==============================================================================
///
/// @file Client.c
///
///
/// @brief A test TLS client using several TLS libraries.
///
/// Copyright (c) 2023 Rockwell Automation Technologies, Inc.
/// All rights reserved.
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


#include <crazywolf/Common.h>
#include <crazywolf/TlsLib.h>
#include <crazywolf/Platform.h>
#include <crazywolf/Environment.h> // Generated header, look into CMake.


//-----------------------------------------------------------------------------
// Constants
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Macros
//-----------------------------------------------------------------------------



#define CW_CLIENT_FLAG_NO_BASIC 0x01
#define CW_CLIENT_FLAG_NO_1BY1 0x02
#define CW_CLIENT_FLAG_NO_ATONCE 0x04

#define CW_CLIENT_TESTSTR(payload, flags)\
        cw_Client_SendTestMsg(sd, pSecureSocketCtx, payload, sizeof(payload) - 1, flags)
#define CW_CLIENT_TESTMSG(payloadBytes, payload, flags)\
        cw_Client_SendTestMsg(sd, pSecureSocketCtx, payload, payloadBytes, flags)


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


static void cw_Client_TlsClient(uint32_t ip4Addr,
                                uint16_t port,
                                SuiteCfg_t* pSc);

static void cw_Client_DtlsClient(uint32_t ip4Addr,
                                 uint16_t port,
                                 SuiteCfg_t* pSc);

//-----------------------------------------------------------------------------
// Variable definitions
//-----------------------------------------------------------------------------


static Msg_t cw_Client_msg;

//-----------------------------------------------------------------------------
// Function definitions
//-----------------------------------------------------------------------------


static void cw_Client_SendTestMsg(int sd,
                                  void* pSecureSocketCtx,
                                  uint8_t* pData,
                                  size_t dataBytes)
{
    cw_Client_msg.str.payloadBytesBe = CW_Platform_Htons((uint16_t)dataBytes);
    cw_Client_msg.str.zero = 0;
    memcpy(cw_Client_msg.str.payload, pData, dataBytes);

    printf("Testing following message (%u bytes):\n%s\n",
           (unsigned int)dataBytes,
           pData);

    CW_TlsLib_SendAll(sd,
                      pSecureSocketCtx,
                      cw_Client_msg.msg,
                      dataBytes+2);
}


static void cw_Client_SendToTestMsg(int sd,
                                    void* pSecureSocketCtx,
                                    uint32_t serverIp4,
                                    uint16_t port,
                                    uint8_t* pData,
                                    size_t dataBytes)
{
    cw_Client_msg.str.payloadBytesBe = CW_Platform_Htons((uint16_t)dataBytes);
    cw_Client_msg.str.zero = 0;
    memcpy(cw_Client_msg.str.payload, pData, dataBytes);

    printf("Testing following message (%u bytes):\n%s\n",
           (unsigned int)dataBytes,
           pData);

    CW_TlsLib_SendToAll(sd,
                        pSecureSocketCtx,
                        serverIp4,
                        port,
                        cw_Client_msg.msg,
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
static void cw_Client_TlsClient(uint32_t ip4Addr,
                                uint16_t port,
                                SuiteCfg_t* pSc)
{
    CW_Common_AllocLogMarkerBegin("Context");
    uint8_t* pAllocaHint = CW_Common_Allocacheck();
#if defined(CW_ENV_DEBUG_ENABLE)
    printf("Connecting server\n");
#endif // defined(CW_ENV_DEBUG_ENABLE)

    int sd = CW_Platform_Socket(true);

    if (sd == -1) // INVALID_SOCKET undef in Unix
    {
        CW_Common_Die("can't get sd");
    }

    if (CW_Platform_Connect(sd, ip4Addr, port) == -1)
    {
        CW_Common_Die("sd connect failed");
    }

#if defined(CW_ENV_DEBUG_ENABLE)
    printf("Server %d:%d connected\n", ip4Addr, port);
#endif // defined(CW_ENV_DEBUG_ENABLE)


    printf("TLS: Picking %s isEcc == %d\n",
           pSc->pCipherSuite,
           pSc->isEcc);

    void* pSecurityCtx = NULL;

    if (pSc->isEcc)
    {
        // ECC
        pSecurityCtx = CW_TlsLib_CreateSecurityContext(false,
                                                       CW_CACERT_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       CW_DEVCERT_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       CW_DEVKEY_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       true);
    }
    else
    {
        // RSA
        pSecurityCtx = CW_TlsLib_CreateSecurityContext(false,
                                                       CW_CACERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       CW_DEVCERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       CW_DEVKEY_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       true);
    }
    CW_Common_AllocLogMarkerEnd("Context");
    CW_Common_AllocLogMarkerBegin("Handshake");

    void* pSecureSocketCtx = CW_TlsLib_MakeSocketSecure(sd, pSecurityCtx);

    CW_TlsLib_ClientHandshake(sd, pSecureSocketCtx);
    CW_Common_AllocLogMarkerEnd("Handshake");
    CW_Common_AllocLogMarkerBegin("Message");


    // Let's test!
#if defined(CW_ENV_DEBUG_ENABLE)
    printf("Hello world test\n");
#endif // defined(CW_ENV_DEBUG_ENABLE)
    cw_Client_SendTestMsg(sd,
                          pSecureSocketCtx,
                          "Hello world",
                          sizeof("Hello world")-1);
    CW_Common_AllocLogMarkerEnd("Message");

    CW_TlsLib_UnmakeSocketSecure(sd, pSecureSocketCtx);
    CW_Platform_CloseSocket(sd);
    CW_TlsLib_DestroySecureContext(pSecurityCtx);


    CW_Common_Allocaprint(pAllocaHint);
    CW_Platform_FlushStdout();
} // End: cw_Client_TlsClient()


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
static void cw_Client_DtlsClient(uint32_t ip4Addr,
                                 uint16_t port,
                                 SuiteCfg_t* pSc)
{
    CW_Common_AllocLogMarkerBegin("Context");

    uint8_t* pAllocaHint = CW_Common_Allocacheck();

    int sd = CW_Platform_Socket(false);

    if (sd == -1) // INVALID_SOCKET undef in Unix
    {
        CW_Common_Die("can't get sd");
    }

    printf("DTLS: Picking %s isEcc == %d\n",
           pSc->pCipherSuite,
           pSc->isEcc);

    void* pSecurityCtx = NULL;

    if (pSc->isEcc)
    {
        // ECC
        pSecurityCtx = CW_TlsLib_CreateSecurityContext(false,
                                                       CW_CACERT_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       CW_DEVCERT_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       CW_DEVKEY_ECC_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       false);
    }
    else
    {
        // RSA
        pSecurityCtx = CW_TlsLib_CreateSecurityContext(false,
                                                       CW_CACERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       CW_DEVCERT_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_PEM,
                                                       CW_DEVKEY_RSA_PATH,
                                                       TLSLIB_FILE_TYPE_DER,
                                                       pSc->pCipherSuite,
                                                       false);
    }

    CW_Common_AllocLogMarkerEnd("Context");
    CW_Common_AllocLogMarkerBegin("Handshake");

    size_t peerAddrSize = 0;
    void* pPeerAddr = CW_Platform_CreatePeerAddr4(&peerAddrSize, ip4Addr, port);
    void* pSecureSocketCtx = CW_TlsLib_MakeDtlsSocketSecure(&sd,
                                                            pSecurityCtx,
                                                            pPeerAddr,
                                                            peerAddrSize);

    CW_TlsLib_ClientHandshake(sd, pSecureSocketCtx);

    CW_Common_AllocLogMarkerEnd("Handshake");
    CW_Common_AllocLogMarkerBegin("Message");

    // Let's test!
#if defined(CW_ENV_DEBUG_ENABLE)
    printf("Hello world test\n");
#endif // defined(CW_ENV_DEBUG_ENABLE)
    cw_Client_SendToTestMsg(sd,
                            pSecureSocketCtx,
                            ip4Addr,
                            port,
                            "Hello world",
                            sizeof("Hello world")-1);

    CW_Common_AllocLogMarkerEnd("Message");

    CW_TlsLib_UnmakeSocketSecure(sd, pSecureSocketCtx);
    CW_Platform_CloseSocket(sd);
    CW_TlsLib_DestroySecureContext(pSecurityCtx);
    CW_Platform_DeletePeerAddr4(pPeerAddr);


    CW_Common_Allocaprint(pAllocaHint);
    CW_Platform_FlushStdout();
} // End: cw_Client_DtlsClient()


//------------------------------------------------------------------------------
///
/// @brief Entry point for the simple TLS Client
///
//------------------------------------------------------------------------------
int main(int argc, char** argv)
{
    CW_Platform_Startup();
    CW_Common_Startup("client", CW_TlsLib_GetName());
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
        printf("USAGE: <crazywolf-XX-client.exe> [server_ip]\n");
        exit(-1);
    }


    uint32_t ip4Addr = CW_Platform_GetIp4Addr(pServerIp4);

    CW_Common_SetIp4Port(ip4Addr, port);
    char testName[128];

    for (int id = 0; ;id++)
    {
        SuiteCfg_t* pSc = CW_Common_GetSuiteCfg(id);
        if (pSc != NULL)
        {

            size_t wouldBeWritten = snprintf(testName, sizeof(testName),
                                             "Test: TLS %s",
                                             pSc->pCipherSuite);
            if (wouldBeWritten > sizeof(testName))
            {
                CW_Common_Die("cannot write test marker");
            }

            CW_Common_AllocLogMarkerBegin(testName);
            cw_Client_TlsClient(ip4Addr, port, pSc);
            CW_Common_AllocLogMarkerEnd(testName);
            CW_Platform_Sleep(1);
        }
        else
        {
            break;
        }
    }

    for (int id = 0; ;id++)
    {
        SuiteCfg_t* pSc = CW_Common_GetSuiteCfg(id);
        if (pSc != NULL)
        {
            size_t wouldBeWritten = snprintf(testName, sizeof(testName),
                                             "Test: DTLS %s",
                                             pSc->pCipherSuite);
            if (wouldBeWritten > sizeof(testName))
            {
                CW_Common_Die("cannot write test marker");
            }

            CW_Common_AllocLogMarkerBegin(testName);
            cw_Client_DtlsClient(ip4Addr, port, pSc);
            CW_Common_AllocLogMarkerEnd(testName);
            CW_Platform_Sleep(1);
        }
        else
        {
            break;
        }
    }


    printf("FINISHED\n");



    CW_TlsLib_Shutdown();
    CW_Common_Shutdown();
    CW_Platform_Shutdown();

    return 0;
} // End: main()


#if 0
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
CW_TlsLib_SendAll(sd,
                  pSecurityCtx,
                  cw_Client_msg.str.payload,
                  CW_Platform_Ntohs(cw_Client_msg.str.payloadBytesBe));
printf("\t one-by-one\n");
CW_TlsLib_SendOneByOneByte(sd,
                           pSecurityCtx,
                           cw_Client_msg.str.payload,
                           CW_Platform_Ntohs(cw_Client_msg.str.payloadBytesBe));
printf("\t at once!\n");
CW_TlsLib_SendAllInOne(sd,
                       pSecurityCtx,
                       cw_Client_msg.str.payload,
                       CW_Platform_Ntohs(cw_Client_msg.str.payloadBytesBe));
printf("\t DONE!\n");

printf("Test case 3: Zeroes and newlines\n");
cw_Client_msg.str.payloadBytesBe = CW_Platform_Htons(4);
cw_Client_msg.str.payload[0] = '0';
cw_Client_msg.str.payload[1] = '\0';
cw_Client_msg.str.payload[2] = 'n';
cw_Client_msg.str.payload[3] = '\n';

printf("\t HAPPY\n");
CW_TlsLib_SendAll(sd,
                  pSecurityCtx,
                  cw_Client_msg.str.payload,
                  CW_Platform_Ntohs(cw_Client_msg.str.payloadBytesBe));
printf("\t one-by-one\n");
CW_TlsLib_SendOneByOneByte(sd,
                           pSecurityCtx,
                           cw_Client_msg.str.payload,
                           CW_Platform_Ntohs(cw_Client_msg.str.payloadBytesBe));
printf("\t at once!\n");
CW_TlsLib_SendAllInOne(sd,
                       pSecurityCtx,
                       cw_Client_msg.str.payload,
                       CW_Platform_Ntohs(cw_Client_msg.str.payloadBytesBe));
printf("\t DONE!\n");


static void cw_Client_SendTestMsg(int sd,
                                  void* pSecureSocketCtx,
                                  uint8_t* pData,
                                  size_t dataBytes,
                                  uint8_t flags)
{
    cw_Client_msg.str.payloadBytesBe = CW_Platform_Htons((uint16_t)dataBytes);
    cw_Client_msg.str.zero = 0;
    memcpy(cw_Client_msg.str.payload, pData, dataBytes);

    printf("Testing following message (%u bytes):\n%s\n",
           (unsigned int)dataBytes,
           pData);

    if ((flags & CW_CLIENT_FLAG_NO_BASIC) == 0)
    {
        printf("Basic test running.\n");
        CW_TlsLib_SendAll(sd,
                          pSecureSocketCtx,
                          cw_Client_msg.msg,
                          dataBytes+2);
        printf("Basic test DONE.\n");
    }
    else
    {
        printf("Basic test disabled.\n");
    }

    if ((flags & CW_CLIENT_FLAG_NO_1BY1) == 0)
    {
        printf("1-by-1 test running.\n");
        CW_TlsLib_SendOneByOneByte(sd,
                                   pSecureSocketCtx,
                                   cw_Client_msg.msg,
                                   dataBytes+2);
        printf("1-by-1 test DONE.\n");
    }
    else
    {
        printf("1-by-1 test disabled.\n");
    }

    if ((flags & CW_CLIENT_FLAG_NO_ATONCE) == 0)
    {
        printf("All-at-once test running.\n");
        CW_TlsLib_SendAllInOne(sd,
                               pSecureSocketCtx,
                               cw_Client_msg.msg,
                               dataBytes+2);
        printf("All-at-once test DONE.\n");
    }
    else
    {
        printf("All-at-once test disabled.\n");
    }
}
#endif
