//==============================================================================
///
/// @file Tlslib.h
///
///
/// @brief TLS Lib abstraction api
///
/// Copyright (c) 2023 Rockwell Automation Technologies, Inc.
/// All rights reserved.
//==============================================================================
#if !defined(CW_TLSLIB_H)
#define CW_TLSLIB_H


//-----------------------------------------------------------------------------
///
/// @brief Init security library.
///
//-----------------------------------------------------------------------------
void CW_Tlslib_Startup(void);

//-----------------------------------------------------------------------------
///
/// @brief Init security library.
///
/// @param[in] socket Socket to make secure.
///
/// @return opaque handle of the secure context.
///
//-----------------------------------------------------------------------------
void* CW_Tlslib_MakeSocketSecure(int socket);

void CW_TlsLib_Handshake(void* pCtx);


//-----------------------------------------------------------------------------
///
/// @brief Shut the security library down.
///
//-----------------------------------------------------------------------------
void CW_Tlslib_Shutdown(void);

#endif // !defined(CW_TLSLIB_H)
