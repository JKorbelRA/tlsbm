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

static int cw_Server_TlsServer(uint16_t port, char* pCertDirPath);


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
static int cw_Server_TlsServer(uint32_t ip4Addr,
                               uint16_t port,
                               char* pCertDirPath)
{
    void* pSecurityCtx = CW_TlsLib_CreateSecurityContext(true,
                                                         "caCert.pem",
                                                         TLSLIB_FILE_TYPE_PEM,
                                                         "devCert.pem",
                                                         TLSLIB_FILE_TYPE_PEM,
                                                         "devKey.pem",
                                                         TLSLIB_FILE_TYPE_PEM,
                                                         "ECDHE-ECDSA-AES128-SHA256");


    int listenSd = CW_Platform_Socket(true);
    if (listenSd == -1) //INVALID_SOCKET undef on Unix
    {
        CW_Common_Die("can't create socket");
    }

    CW_Platform_BindAndListen(listenSd, ip4Addr, port);
    printf("Simple SSL server started on port %d\n", port);

    while (true)
    {
        printf("Accepting new client\n");
        int sd = CW_Platform_Accept(listenSd);

        if (sd < 0)
        {
            continue;
        }

        void* pSecureSocketCtx = CW_TlsLib_MakeSocketSecure(sd, pSecurityCtx);

        int res = CW_TlsLib_ServerHandshake(sd, pSecureSocketCtx);
        if (res != 0)
        {
            continue;
        }

        while (res == 0)
        {
            res = CW_TlsLib_Recv(sd,
                                 pSecureSocketCtx,
                                 (uint8_t*)&cw_Server_inMsg.str.payloadBytesBe,
                                 2);
            if (res == 0)
            {
                size_t payloadBytes = CW_Platform_Ntohs(cw_Server_inMsg.str.payloadBytesBe);
                res = CW_TlsLib_Recv(sd,
                                     pSecureSocketCtx,
                                     (uint8_t*)&cw_Server_inMsg.str.payloadBytesBe,
                                     payloadBytes);
                if (res == 0)
                {
                    printf("Msg size: %d\nMsg:\n%s",
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


        CW_TlsLib_UnmakeSocketSecure(sd, pSecureSocketCtx);
        CW_Platform_CloseSocket(sd);
    }

    CW_TlsLib_DestroySecureContext(pSecurityCtx);

    return 0;
} // End: cw_Server_TlsServer()


//------------------------------------------------------------------------------
///
/// @brief Entry point for the simple TLS Server
///
//------------------------------------------------------------------------------
int main(int argc, char** argv)
{
    CW_Platform_Startup();
    CW_TlsLib_Startup();

    uint16_t port = SIMPLE_SSL_PORT;
    char* pCertPath = SIMPLE_SSL_CERT_PATH;

    // check args count
    if (argc > 1)
    {
        // TODO enable change port or something else?
    }

    uint32_t ip4Addr = 0;

    int result = cw_Server_TlsServer(ip4Addr, port, pCertPath);

    CW_TlsLib_Shutdown();
    CW_Platform_Shutdown();

    return result;
} // End: main()
