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


//-----------------------------------------------------------------------------
//
// Shut the platform down.
//
//-----------------------------------------------------------------------------
void CW_Platform_BindAndListen(int sd, uint32_t ip4Addr, uint16_t port)
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
