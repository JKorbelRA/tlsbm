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


#define SIMPLE_SSL_PORT 2221
#define SIMPLE_SSL_SERVER_ADDR "127.0.0.1"
#define SIMPLE_SSL_CERT_PATH "cert.pem"

//-----------------------------------------------------------------------------
///
/// @brief Dies with a message.
///
/// @param[in] pErrorMsg - error message
///
//-----------------------------------------------------------------------------
void CW_Common_Die(const char* pErrorMsg);

#endif // !defined(CW_COMMON_H)
