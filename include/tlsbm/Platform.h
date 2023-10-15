//==============================================================================
///
/// @file Platform.h
///
///
/// @brief Platform abstraction api
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
