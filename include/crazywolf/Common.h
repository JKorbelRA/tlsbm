//==============================================================================
///
/// @file Common.h
///
///
/// @brief Common utils for wolf test.
///
/// Copyright (c) 2022 Rockwell Automation Technologies, Inc.
/// All rights reserved.
//==============================================================================
#if !defined(CW_COMMON_H)
#define CW_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


#define SIMPLE_SSL_PORT 2221

#define CW_DEVCERT_RSA_PATH "devCertRsa.pem"
#define CW_CACERT_RSA_PATH "caCertRsa.pem"
#define CW_DEVKEY_RSA_PATH "devKeyRsa.der"

#define CW_DEVCERT_ECC_PATH "devCertEc.pem"
#define CW_CACERT_ECC_PATH "caCertEc.pem"
#define CW_DEVKEY_ECC_PATH "devKeyEc.der"

#define CW_CIPHER_SUITE_RSA_PSK "DHE-PSK-AES128-CBC-SHA256"
#define CW_CIPHER_SUITE_RSA_CERT "DHE-RSA-AES256-SHA256"
#define CW_CIPHER_SUITE_ECC_PSK "ECDHE-PSK-AES128-CBC-SHA256"
#define CW_CIPHER_SUITE_ECC_CERT "ECDHE-ECDSA-AES128-SHA256"

typedef struct
{
    const char* pCipherSuite;
    const char* pCaCert;
    const char* pDevCert;
    const char* pDevKey;
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

uint8_t* CW_Common_Allocacheck(size_t stackMaxBytes);

void CW_Common_Allocaprint(uint8_t* pAlloca,
                           size_t stackMaxBytes);

//-----------------------------------------------------------------------------
///
/// @brief Dies with a message.
///
/// @param[in] pErrorMsg - error message
///
//-----------------------------------------------------------------------------
void CW_Common_Die(const char* pErrorMsg);

void* CW_Common_Malloc(unsigned long size);
void* CW_Common_Realloc(void* ptr, unsigned long size);
void  CW_Common_Free(void* ptr);
void CW_Common_Shutdown(void);
void CW_Common_Startup(const char* pMethodName, const char* pTlsLibName);
const char* CW_Common_GetPskIdentity(void);
uint8_t* CW_Common_GetPsk(size_t* pPskBytes);
void  CW_Common_AllocLogMarkerBegin(const char* pMarker);
void  CW_Common_AllocLogMarkerEnd(const char* pMarker);
SuiteCfg_t* CW_Common_GetCipherSuiteAndFiles(bool isPsk, bool isRsa);
void CW_Common_SetIp4Port(uint32_t ip4Addr, uint16_t port);
void CW_Common_GetIp4Port(uint32_t* pIp4Addr, uint16_t* pPort);
void* CW_Common_Calloc(size_t nitems, size_t itemBytes);

#endif // !defined(CW_COMMON_H)
