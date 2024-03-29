//==============================================================================
///
/// @file Linux.c
///
///
/// @brief Linux platform support.
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
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "../include/tlsbm/Common.h"
#include "../include/tlsbm/Platform.h"

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

//-----------------------------------------------------------------------------
// Global references
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Forward function declarations
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
// Variable definitions
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
// Function definitions
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//
// Init platform.
//
//-----------------------------------------------------------------------------
void TLSBM_Platform_Startup(void)
{
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
void TLSBM_Platform_Shutdown(void)
{
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
int TLSBM_Platform_Socket(bool isStream)
{
    if (isStream)
    {
        return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    else
    {
        int sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
/*
        int flags = fcntl(sd, F_GETFL, 0);

        if (flags >= 0)
        {
            flags |= O_NONBLOCK;
            fcntl(sd, F_SETFL, (int)flags);
        }
*/
        return sd;
    }
}

void* TLSBM_Platform_CreatePeerAddr4(size_t* pPeerAddrSize, uint32_t ip4Addr, uint16_t port)
{
    struct sockaddr_in* pPeerAddr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    if (pPeerAddr == NULL)
    {
        TLSBM_Common_Die("peer address allocation failed\n");
    }

    memset(pPeerAddr, sizeof(struct sockaddr_in), 0);
    pPeerAddr->sin_family = AF_INET;
    pPeerAddr->sin_port = htons(port);
    pPeerAddr->sin_addr.s_addr = ip4Addr;

    *pPeerAddrSize = sizeof(struct sockaddr_in);

    return pPeerAddr;
}

void TLSBM_Platform_DeletePeerAddr4(void* pPeerAddr)
{
    free(pPeerAddr);
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
int TLSBM_Platform_Connect(int sd, uint32_t ip4Addr, uint16_t port)
{
    struct sockaddr_in srvAddr;
    memset(&srvAddr, sizeof(srvAddr), 0);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(port);
    srvAddr.sin_addr.s_addr = ip4Addr;

    int res = connect(sd,
                      (struct sockaddr*)&srvAddr,
                      sizeof(srvAddr)) == -1;
    return res;
}

int TLSBM_Platform_ConnectPa(int sd, void* pPeerAddr, size_t peerAddrSize)
{
    int res = connect(sd,
                      (struct sockaddr*)pPeerAddr,
                      peerAddrSize) == -1;
    return res;
}

void TLSBM_Platform_Bind(int sd, uint32_t ip4Addr, uint16_t port)
{
    int on = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
    {
        TLSBM_Common_Die("setsockopt SO_REUSEADDR failed\n");
    }

    on = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
    {
        TLSBM_Common_Die("setsockopt SO_REUSEPORT failed\n");
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip4Addr;
    addr.sin_port = htons(port);

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
    {
        printf("bind error %d", errno);
        TLSBM_Common_Die("can't bind socket\n");
    }
}


void TLSBM_Platform_GetIp4PortFromPeerAddr(void* pPeerAddrIn,
                                        uint32_t* pIp4Addr,
                                        uint16_t* pPort)
{
    if (pPeerAddrIn == NULL)
    {
        TLSBM_Common_Die("pPeerAddrIn bad arg failed\n");
    }
    if (pIp4Addr == NULL)
    {
        TLSBM_Common_Die("pIp4Addr bad arg failed\n");
    }
    if (pPort == NULL)
    {
        TLSBM_Common_Die("pPort bad arg failed\n");
    }

    struct sockaddr_in* pPeerAddr = (struct sockaddr_in*)pPeerAddrIn;


    if (pPeerAddr->sin_family != AF_INET)
    {
        TLSBM_Common_Die("pPeerAddr->sin_family != AF_INET\n");
    }

    *pIp4Addr = pPeerAddr->sin_addr.s_addr;
    *pPort = pPeerAddr->sin_port;
}


void TLSBM_Platform_Listen(int sd)
{
    if (listen(sd, SOMAXCONN) == -1)
    {
        TLSBM_Common_Die("can't listen to socket\n");
    }
}

void TLSBM_Platform_FlushStdout(void)
{
    fflush(stdout);
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
int TLSBM_Platform_Accept(int listenSd)
{
    struct sockaddr_in  clientAddr;
    int clientLen = sizeof(clientAddr);

    int clientSocket = (int)accept(listenSd,
                                   (struct sockaddr*)&clientAddr,
                                   &clientLen);

    return clientSocket;
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
void TLSBM_Platform_CloseSocket(int sd)
{
    (void)close(sd);
}


int TLSBM_Platform_Recvfrom(int sd,
                         uint8_t* pData,
                         size_t dataBytes,
                         void* pPeerAddr,
                         size_t* pPeerAddrSize)
{
    unsigned int outSize = (unsigned int)*pPeerAddrSize;
    int recvd = recvfrom(sd,
                    pData,
                    (int)dataBytes,
                    0,
                    (struct sockaddr*)pPeerAddr,
                    &outSize);
    *pPeerAddrSize = outSize;
    return recvd;

}

void TLSBM_Platform_Sleep(uint32_t s)
{
    sleep(s);
}

int TLSBM_Platform_RecvfromPeek(int sd,
                             uint8_t* pData,
                             size_t dataBytes,
                             void* pPeerAddr,
                             size_t* pPeerAddrSize)
{
    unsigned int outSize = (unsigned int)*pPeerAddrSize;
    int recvd = recvfrom(sd,
                    pData,
                    (int)dataBytes,
                    MSG_PEEK,
                    (struct sockaddr*)pPeerAddr,
                    &outSize);
    *pPeerAddrSize = outSize;
    return recvd;

}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
uint16_t TLSBM_Platform_Htons(uint16_t hostNum)
{
    return htons(hostNum);
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
uint16_t TLSBM_Platform_Ntohs(uint16_t networkNum)
{
    return ntohs(networkNum);
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
uint32_t TLSBM_Platform_GetIp4Addr(const char* pIp4Str)
{
    return inet_addr(pIp4Str);
}
