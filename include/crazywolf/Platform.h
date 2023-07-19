//==============================================================================
///
/// @file Platform.h
///
///
/// @brief Platform abstraction api
///
/// Copyright (c) 2023 Rockwell Automation Technologies, Inc.
/// All rights reserved.
//==============================================================================
#if !defined(CW_PLATFORM_H)
#define CW_PLATFORM_H


#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>


//-----------------------------------------------------------------------------
///
/// @brief Init platform.
///
//-----------------------------------------------------------------------------
void CW_Platform_Startup(void);


//-----------------------------------------------------------------------------
///
/// @brief Shut the platform down.
///
//-----------------------------------------------------------------------------
void CW_Platform_Shutdown(void);

int CW_Platform_Socket(bool isStream);
int CW_Platform_Connect(int sd, uint32_t ip4Addr, uint16_t port);
void CW_Platform_BindAndListen(int sd, uint32_t ip4Addr, uint16_t port);
int CW_Platform_Accept(int listenSd);
void CW_Platform_CloseSocket(int sd);
uint16_t CW_Platform_Htons(uint16_t hostNum);
uint16_t CW_Platform_Ntohs(uint16_t networkNum);
uint32_t CW_Platform_GetIp4Addr(const char* pIp4Str);
void CW_Platform_FlushStdout(void);
void* CW_Platform_CreatePeerAddr4(size_t* pPeerAddrSize, uint32_t ip4Addr, uint16_t port);
void CW_Platform_DeletePeerAddr4(void* pPeerAddr);

#endif // !defined(CW_PLATFORM_H)
