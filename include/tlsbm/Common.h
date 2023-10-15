//==============================================================================
///
/// @file Common.h
///
///
/// @brief Common utils for wolf test.
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
#if !defined(TLSBM_COMMON_H)
#define TLSBM_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


#define SIMPLE_SSL_PORT 2221

#define TLSBM_CACERT_RSA_PATH "caCertRsa.pem"
#define TLSBM_DEVCERT_RSA_PATH "devCertRsa.pem"
#define TLSBM_DEVKEY_RSA_PATH "devKeyRsa.der"

#define TLSBM_CACERT_ECC_PATH "caCertEc.pem"
#define TLSBM_DEVCERT_ECC_PATH "devCertEc.pem"
#define TLSBM_DEVKEY_ECC_PATH "devKeyEc.der"

#define TLSBM_CIPHER_SUITE_RSA_PSK "DHE-PSK-AES128-CBC-SHA256"
#define TLSBM_CIPHER_SUITE_RSA_CERT "DHE-RSA-AES256-SHA256"

#define TLSBM_CIPHER_SUITE_ECC_PSK "ECDHE-PSK-AES128-CBC-SHA256"
#define TLSBM_CIPHER_SUITE_ECC_CERT "ECDHE-ECDSA-AES128-SHA256"
#define TLSBM_CIPHER_SUITE_ECC_CERT_GCM "ECDHE-ECDSA-AES128-GCM-SHA256"
#define TLSBM_CIPHER_SUITE_ECC_PSK_NULL "ECDHE-PSK-NULL-SHA256"
#define TLSBM_CIPHER_SUITE_ECC_CHACHA20_POLY1305 "ECDHE-PSK-CHACHA20-POLY1305"

typedef struct
{
    const char* pCipherSuite;
    bool isEcc;
} SuiteCfg_t;

typedef union
{
    struct
    {
        uint16_t payloadBytesBe;
        uint8_t payload[UINT16_MAX];
        uint8_t zero;
    } str;

    uint8_t msg[UINT16_MAX + sizeof(uint16_t) + sizeof(uint8_t)];
} Msg_t;

#define MSG_UDP_MTU 1500

typedef union
{
    struct
    {
        uint16_t payloadBytesBe;
        uint8_t payload[MSG_UDP_MTU];
        uint8_t zero;
    } str;

    uint8_t msg[MSG_UDP_MTU + sizeof(uint16_t) + sizeof(uint8_t)];
} MsgDtls_t;

#define ALLOCACHECK_STACK_BYTES 50000

void* TLSBM_Common_Allocacheck(void);

void TLSBM_Common_Allocaprint(void* pAllocaHint);

//-----------------------------------------------------------------------------
///
/// @brief Dies with a message.
///
/// @param[in] pErrorMsg - error message
///
//-----------------------------------------------------------------------------
void TLSBM_Common_Die(const char* pErrorMsg);

void* TLSBM_Common_Malloc(unsigned long size);
void* TLSBM_Common_Realloc(void* ptr, unsigned long size);
void  TLSBM_Common_Free(void* ptr);
void TLSBM_Common_Shutdown(void);
void TLSBM_Common_Startup(const char* pMethodName, const char* pTlsLibName);
const char* TLSBM_Common_GetPskIdentity(void);
uint8_t* TLSBM_Common_GetPsk(size_t* pPskBytes);
void  TLSBM_Common_AllocLogMarkerBegin(const char* pMarker);
void  TLSBM_Common_AllocLogMarkerEnd(const char* pMarker);
SuiteCfg_t* TLSBM_Common_GetSuiteCfg(int id);
void TLSBM_Common_SetIp4Port(uint32_t ip4Addr, uint16_t port);
void TLSBM_Common_GetIp4Port(uint32_t* pIp4Addr, uint16_t* pPort);
void* TLSBM_Common_Calloc(size_t nitems, size_t itemBytes);

#endif // !defined(TLSBM_COMMON_H)
