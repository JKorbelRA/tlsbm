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
#if !defined(TLSBM_PLATFORM_H)
#define TLSBM_PLATFORM_H


#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>


//-----------------------------------------------------------------------------
///
/// @brief Init platform.
///
//-----------------------------------------------------------------------------
void TLSBM_Platform_Startup(void);


//-----------------------------------------------------------------------------
///
/// @brief Shut the platform down.
///
//-----------------------------------------------------------------------------
void TLSBM_Platform_Shutdown(void);

int TLSBM_Platform_Socket(bool isStream);
int TLSBM_Platform_Connect(int sd, uint32_t ip4Addr, uint16_t port);
int TLSBM_Platform_ConnectPa(int sd, void* pPeerAddr, size_t peerAddrSize);
void TLSBM_Platform_Bind(int sd, uint32_t ip4Addr, uint16_t port);
void TLSBM_Platform_Listen(int sd);
int TLSBM_Platform_Accept(int listenSd);
int TLSBM_Platform_Recvfrom(int sd,
                         uint8_t* pData,
                         size_t dataBytes,
                         void* pPeerAddr,
                         size_t* pPeerAddrSize);
int TLSBM_Platform_RecvfromPeek(int sd,
                             uint8_t* pData,
                             size_t dataBytes,
                             void* pPeerAddr,
                             size_t* pPeerAddrSize);
void TLSBM_Platform_CloseSocket(int sd);
void TLSBM_Platform_Sleep(uint32_t s);
uint16_t TLSBM_Platform_Htons(uint16_t hostNum);
uint16_t TLSBM_Platform_Ntohs(uint16_t networkNum);
uint32_t TLSBM_Platform_GetIp4Addr(const char* pIp4Str);
void TLSBM_Platform_FlushStdout(void);
void* TLSBM_Platform_CreatePeerAddr4(size_t* pPeerAddrSize, uint32_t ip4Addr, uint16_t port);
void TLSBM_Platform_DeletePeerAddr4(void* pPeerAddr);

#endif // !defined(TLSBM_PLATFORM_H)
