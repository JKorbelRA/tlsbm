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
#define SIMPLE_SSL_SERVER_ADDR "127.0.0.1"
#define SIMPLE_SSL_CERT_PATH "cert.pem"


#if defined(CW_ENV_TEST_RSA)
    #define CW_DEVCERT_PATH "devCertRsa.pem"
    #define CW_CACERT_PATH "caCertRsa.pem"
    #define CW_DEVKEY_PATH "devKeyRsa.der"
    #if defined(CW_ENV_TEST_PSK)
        #define CW_CIPHER_SUITE "DHE-PSK-AES128-CBC-SHA256"
    #else
        #define CW_CIPHER_SUITE "RSA-AES256-CBC-SHA256"
    #endif
#else
    #define CW_DEVCERT_PATH "devCertEc.pem"
    #define CW_CACERT_PATH "caCertEc.pem"
    #define CW_DEVKEY_PATH "devKeyEc.der"
    #if defined(CW_ENV_TEST_PSK)
        #define CW_CIPHER_SUITE "ECDHE-PSK-AES128-CBC-SHA256"
    #else
        #define CW_CIPHER_SUITE "ECDHE-ECDSA-AES128-SHA256"
    #endif
#endif

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
void CW_Common_Startup(void);const char* CW_Common_GetPskIdentity(void);
uint8_t* CW_Common_GetPsk(size_t* pPskBytes);
void  CW_Common_AllocLogMarkerBegin(const char* pMarker);
void  CW_Common_AllocLogMarkerEnd(const char* pMarker);

#endif // !defined(CW_COMMON_H)
