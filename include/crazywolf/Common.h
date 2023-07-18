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
#include <stdint.h>
#include <stdbool.h>


#define SIMPLE_SSL_PORT 2221
#define SIMPLE_SSL_SERVER_ADDR "127.0.0.1"
#define SIMPLE_SSL_CERT_PATH "cert.pem"


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

void* CW_Common_Malloc(unsigned long size, void* heap, int type);
void* CW_Common_Realloc(void* ptr, unsigned long size, void* heap,
                             int type);
void  CW_Common_Free(void* ptr, void* heap, int type);
void CW_Common_Shutdown(void);
void CW_Common_Startup(void);

#endif // !defined(CW_COMMON_H)
