//==============================================================================
///
/// @file server.c
///
///
/// @brief A test TLS server using wolfsSLL library.
///
/// Copyright (c) 2022 Rockwell Automation Technologies, Inc.
/// All rights reserved.
//==============================================================================


//------------------------------------------------------------------------------
// Include files
//------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#else
#include <winsock2.h>
#include <ws2def.h>
#endif

// wolfSSL
#include <wolfssl/ssl.h>
#include "Common.h"

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

//------------------------------------------------------------------------------
// Variable definitions
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Function definitions
//------------------------------------------------------------------------------


/// @brief init connection socket
/// @param[out] pSocket - pointer to socket
/// @param[in] port - port
/// @return 0 on success

int tcpListen(int* pSocket, uint16_t port)
{
    *pSocket = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*pSocket == -1) //INVALID_SOCKET undef on Unix
    {
        CW_Common_Die("can't create socket");
    }

#ifdef WIN32
    char on = 1;
    int len = sizeof(on);
    if (setsockopt(*pSocket, SOL_SOCKET, SO_REUSEADDR, &on, len) < 0)
    {
        CW_Common_Die("setsockopt SO_REUSEADDR failed");
    }
#endif

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(*pSocket, (struct sockaddr*)&addr, sizeof(addr)) == -1) //SOCKET_ERROR  undef on Unix
    {
        CW_Common_Die("can't bind socket");
    }

    if (listen(*pSocket, SOMAXCONN) == -1) //SOCKET_ERROR undef on Unix
    {
        CW_Common_Die("can't listen to socket");
    }

    return 0;
}// End: tcpListen()

/// @brief readWolfSSLData, reads data of specified length
/// @param[in] pSsl - wolfSSL session
/// @param[out] pBuffer - data buffer - buffer size shoud be > then bytes to read
/// @param[in] len - data length to read
/// @param[out] pErrBuf - buffer for potential wolfSSL error message
/// @return returns 0 if all required bytes read

int readWolfSSLData(WOLFSSL* pSsl, char* pBuffer, int len, char* pErrBuffer)
{
    int offset = 0;
    int err = 0;

    // read while not [len] bytes read or some connection error
    do {
        err = 0;
        int ret = wolfSSL_read(pSsl, pBuffer + offset, len - offset);
        if (ret <= 0) {
            err = wolfSSL_get_error(pSsl, 0);
        }
        else
        {
            offset += ret;
        }
    } while (offset < len &&
        (err == 0 || err == WC_PENDING_E));

    if (offset == len) {
        return 0;
    }
    printf("wolfSSL read error %d, %s!\n", err, wolfSSL_ERR_error_string(err, pErrBuffer));
    return 1;
}


/// @brief main client function, reads inputBuffer from stdin and send it to the SSL server
/// @param[in] port - comm port
/// @param[in] pCertDirPath - path to certificates
/// @return return 0 on success

int simpleSSLServer(uint16_t port, char* pCertDirPath)
{
    // wolfSSL init
    WOLFSSL_METHOD* pMethod = wolfTLSv1_2_server_method();
    if (pMethod == NULL)
    {
        CW_Common_Die("wolf method error");
    }

    WOLFSSL_CTX* pCtx = wolfSSL_CTX_new(pMethod);
    if (pCtx == NULL)
    {
        CW_Common_Die("wolf ctx error");
    }

    if (!wolfSSL_CTX_set_cipher_list(pCtx, "ECDHE-ECDSA-AES128-SHA256"))
    {
        CW_Common_Die("wolf cipher list error");
    }

    //large buffers allocated on heap
    static char certFile[MAX_PATH];

    snprintf(certFile, sizeof(certFile), "%s/ca-ecc-cert.pem", pCertDirPath);

    if (wolfSSL_CTX_load_verify_locations(pCtx, certFile, 0) != WOLFSSL_SUCCESS)
    {
        CW_Common_Die("load ca-ecc-cert.pem error");
    }

    snprintf(certFile, sizeof(certFile), "%s/server-ecc.pem", pCertDirPath);

    if (wolfSSL_CTX_use_certificate_file(pCtx, certFile, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
    {
        CW_Common_Die("load server-ecc.pem error");
    }

    snprintf(certFile, sizeof(certFile), "%s/ecc-key.pem", pCertDirPath);

    if (wolfSSL_CTX_use_PrivateKey_file(pCtx, certFile, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
    {
        CW_Common_Die("load ecc-key.pem error");
    }

    if (!wolfSSL_CTX_set_cipher_list(pCtx, "ECDHE-ECDSA-AES128-SHA256"))
    {
        CW_Common_Die("wolf cipher list error");
    }

    // bind to socket and wait for client requests
    int socket = 0;
    tcpListen(&socket, port);
    printf("Simple SSL server started on port %d\n", port);

    // wait for clients
    int clientSocket = 0;
    struct sockaddr_in  clientAddr;
    int clientLen = sizeof(clientAddr);

    //large buffers allocated on heap
    static char errBuffer[WOLFSSL_MAX_ERROR_SZ];

    while ((clientSocket = (int)accept(socket, (struct sockaddr*)&clientAddr, &clientLen)) != -1)
    {
        WOLFSSL* pSsl = wolfSSL_new(pCtx);

        if (pSsl == NULL)
        {
            CW_Common_Die("wolf ssl error");
        }

        wolfSSL_set_fd(pSsl, clientSocket);

        int ret = 0;
        int err = 0;
        do {
            err = 0;
            ret = wolfSSL_accept(pSsl);
            if (ret != WOLFSSL_SUCCESS)
            {
                err = wolfSSL_get_error(pSsl, 0);
            }
        } while (err == WC_PENDING_E);
        if (ret != WOLFSSL_SUCCESS) {
            printf("wolf accept error = %d, %s\n", err, wolfSSL_ERR_error_string(err, errBuffer));
            printf("wolf accept failed\n");
            wolfSSL_free(pSsl);
            CloseSocket(clientSocket);
            continue;
        }
        printf("client accepted\n");

        //large buffers allocated on heap
        static char msgBuffer[USHRT_MAX + 2];
        while (readWolfSSLData(pSsl, msgBuffer, 2, errBuffer) == 0)
        {
            // get message size and read data
            uint16_t msgLen = ntohs(*((uint16_t*)msgBuffer));

            if (readWolfSSLData(pSsl, msgBuffer + 2, msgLen, errBuffer) == 0)
            {
                msgBuffer[msgLen + 2] = '\0';
                fprintf(stdout, "[%d] ", msgLen);
                fprintf(stdout, "%s\n", msgBuffer + 2);
            }
            else
            {
                // message read failed
                break;
            }
        }
        wolfSSL_shutdown(pSsl);
        wolfSSL_free(pSsl);
        CloseSocket(clientSocket);
    }

    CloseSocket(socket);
    wolfSSL_CTX_free(pCtx);

    return 0;
} // End: simpleSSLServer()

//------------------------------------------------------------------------------
///
/// @brief Entry point for the simple SSL Server
///
//------------------------------------------------------------------------------

int main(int argc, char** argv)
{
    short port = SIMPLE_SSL_PORT;
    char* certPath = SIMPLE_SSL_CERT_PATH;

    int result = 1;
    // check args count
    if (argc > 1)
    {
        // TODO enable change port or something else?
    }

#ifdef WIN32
    WSADATA wsaData;
    if (WSAStartup(0x0002, &wsaData) != NO_ERROR)
    {
        return 1;
    }
#endif // WIN32
    wolfSSL_Init();
    result = simpleSSLServer(port, certPath);
    wolfSSL_Cleanup();
    return result;
} // End: main()
