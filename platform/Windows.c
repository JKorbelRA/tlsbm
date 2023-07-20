//==============================================================================
///
/// @file Windows.c
///
///
/// @brief Windows platform support.
///
/// Copyright (c) 2023 Rockwell Automation Technologies, Inc.
/// All rights reserved.
//==============================================================================

//------------------------------------------------------------------------------
// Include files
//------------------------------------------------------------------------------
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>

#include <ws2tcpip.h>
#include <windows.h>

#include <crazywolf/Common.h>
#include <crazywolf/Platform.h>

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
void CW_Platform_Startup(void)
{
    WSADATA wsaData;
    int result = WSAStartup(0x0002, &wsaData);
    if (result != NO_ERROR)
    {
        printf("WSAStartup failed with code %d\n", result);
        CW_Common_Die("Exiting");
    }
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
void CW_Platform_Shutdown(void)
{
    int result = WSACleanup();
    if (result != NO_ERROR)
    {
        printf("WSACleanup failed with code %d.\n", result);
        CW_Common_Die("Exiting.\n");
    }
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
int CW_Platform_Socket(bool isStream)
{
    if (isStream)
    {
        return (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    else
    {
        return (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
int CW_Platform_Connect(int sd, uint32_t ip4Addr, uint16_t port)
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


void CW_Platform_Sleep(uint32_t s)
{
    Sleep(s*1000);
}

void CW_Platform_Bind(int sd, uint32_t ip4Addr, uint16_t port)
{
    char on = 1;
    int len = sizeof(on);
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, len) < 0)
    {
        CW_Common_Die("setsockopt SO_REUSEADDR failed");
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip4Addr;
    addr.sin_port = htons(port);

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
    {
        CW_Common_Die("can't bind socket");
    }
}

void CW_Platform_Listen(int sd)
{

    if (listen(sd, SOMAXCONN) == -1)
    {
        CW_Common_Die("can't listen to socket");
    }
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
int CW_Platform_Accept(int listenSd)
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
void CW_Platform_CloseSocket(int sd)
{
    (void)closesocket((SOCKET)sd);
}


int CW_Platform_Recvfrom(int sd,
                         uint8_t* pData,
                         size_t dataBytes,
                         void* pPeerAddr,
                         size_t* pPeerAddrSize)
{
    int outSize = (int)*pPeerAddrSize;
    int recvd = recvfrom(sd,
                    pData,
                    (int)dataBytes,
                    0,
                    (struct sockaddr*)pPeerAddr,
                    &outSize);
    *pPeerAddrSize = outSize;
    return recvd;

}

int CW_Platform_RecvfromPeek(int sd,
                             uint8_t* pData,
                             size_t dataBytes,
                             void* pPeerAddr,
                             size_t* pPeerAddrSize)
{
    int outSize = (int)*pPeerAddrSize;
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
uint16_t CW_Platform_Htons(uint16_t hostNum)
{
    return htons(hostNum);
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
uint16_t CW_Platform_Ntohs(uint16_t networkNum)
{
    return ntohs(networkNum);
}


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
uint32_t CW_Platform_GetIp4Addr(const char* pIp4Str)
{
    uint32_t addr = 0;
    InetPton(AF_INET, pIp4Str, &addr);
    return addr;
}


void* CW_Platform_CreatePeerAddr4(size_t* pPeerAddrSize, uint32_t ip4Addr, uint16_t port)
{
    struct sockaddr_in* pPeerAddr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    if (pPeerAddr == NULL)
    {
        CW_Common_Die("peer address allocation failed\n");
    }

    memset(pPeerAddr, sizeof(struct sockaddr_in), 0);
    pPeerAddr->sin_family = AF_INET;
    pPeerAddr->sin_port = htons(port);
    pPeerAddr->sin_addr.s_addr = ip4Addr;

    if (pPeerAddrSize == NULL)
    {
        CW_Common_Die("peer address size bad arg failed\n");
    }
    *pPeerAddrSize = sizeof(struct sockaddr_in);
    return pPeerAddr;
}


void CW_Platform_GetIp4PortFromPeerAddr(void* pPeerAddrIn,
                                        uint32_t* pIp4Addr,
                                        uint16_t* pPort)
{
    if (pPeerAddrIn == NULL)
    {
        CW_Common_Die("pPeerAddrIn bad arg failed\n");
    }
    if (pIp4Addr == NULL)
    {
        CW_Common_Die("pIp4Addr bad arg failed\n");
    }
    if (pPort == NULL)
    {
        CW_Common_Die("pPort bad arg failed\n");
    }

    struct sockaddr_in* pPeerAddr = (struct sockaddr_in*)pPeerAddrIn;


    if (pPeerAddr->sin_family != AF_INET)
    {
        CW_Common_Die("pPeerAddr->sin_family != AF_INET\n");
    }

    *pIp4Addr = pPeerAddr->sin_addr.s_addr;
    *pPort = pPeerAddr->sin_port;
}


void CW_Platform_DeletePeerAddr4(void* pPeerAddr)
{
    free(pPeerAddr);
}


void CW_Platform_FlushStdout(void)
{
    fflush(stdout);
}

