//==============================================================================
///
/// @file TlsLib.h
///
///
/// @brief TLS Lib abstraction api
///
/// Copyright (c) 2023 Rockwell Automation Technologies, Inc.
/// All rights reserved.
//==============================================================================
#if !defined(CW_TLSLIB_H)
#define CW_TLSLIB_H

typedef enum
{
    TLSLIB_FILE_TYPE_DER,
    TLSLIB_FILE_TYPE_PEM
} TlsLibFileType_t;


//------------------------------------------------------------------------------
///
/// @brief Init security library.
///
//------------------------------------------------------------------------------
void CW_TlsLib_Startup(void);


//------------------------------------------------------------------------------
///
/// @brief Creates a security context. Returns security context handle.
///
/// @return opaque handle of the security context.
///
//------------------------------------------------------------------------------
void* CW_TlsLib_CreateSecurityContext(bool isServer,
                                      const char* pCaCertPath,
                                      TlsLibFileType_t caCertFileType,
                                      const char* pDevCertPath,
                                      TlsLibFileType_t devCertFileType,
                                      const char* pDevKeyPath,
                                      TlsLibFileType_t devKeyFileType,
                                      const char* pCipherList,
                                      bool isTls);


//------------------------------------------------------------------------------
///
/// @brief Makes a sd secure. Returns secure sd context handle.
///
/// @param[in] sd Socket to make secure.
///
/// @param[in] pSecureCtx Pointer to security context created by
/// CW_TlsLib_CreateSecurityContext().
///
/// @return opaque handle of the secure sd context.
///
//------------------------------------------------------------------------------
void* CW_TlsLib_MakeSocketSecure(int sd,
                                 void* pSecureCtx);

void* CW_TlsLib_MakeDtlsSocketSecure(int* pSd,
                                 void* pSecureCtx,
                                 void* pPeerAddr,
                                 size_t peerAddrSize);


//------------------------------------------------------------------------------
///
/// @brief Unmakes security of a sd. Frees secure sd context per
/// its handle.
///
/// @param[in] sd Socket to de-secure.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// CW_TlsLib_MakeSocketSecure().
///
/// @return opaque handle of the secure sd context.
///
//------------------------------------------------------------------------------
void CW_TlsLib_UnmakeSocketSecure(int sd, void* pSecureSocketCtx);


//------------------------------------------------------------------------------
///
/// @brief Destroys a security context.
///
/// @param[in] pSecureCtx Pointer to a security context.
///
/// @return opaque handle of the security context.
///
//------------------------------------------------------------------------------
void CW_TlsLib_DestroySecureContext(void* pSecureCtx);


//------------------------------------------------------------------------------
///
/// @brief Performs client handshake.
///
/// Usually after connect.
///
/// @param[in] sd Socket to perform handshake on.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// CW_TlsLib_MakeSocketSecure().
///
//------------------------------------------------------------------------------
void CW_TlsLib_ClientHandshake(int sd, void* pSecureSocketCtx);


//------------------------------------------------------------------------------
///
/// @brief Performs server handshake.
///
/// Usually after accept.
///
/// @param[in] sd Socket to perform handshake on.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// CW_TlsLib_MakeSocketSecure().
///
/// @retval 0 all ok
/// @retval -1 error
///
//------------------------------------------------------------------------------
int CW_TlsLib_ServerHandshake(int sd, void* pSecureSocketCtx);

//------------------------------------------------------------------------------
///
/// @brief Sends data securely until everything has been sent in a loop.
///
/// @param[in] sd Socket to send data on.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// CW_TlsLib_MakeSocketSecure().
///
/// @param[in] pData Pointer to buffer to send.
///
/// @param[in] dataBytes Size of the buffer to send in bytes.
///
//------------------------------------------------------------------------------
void CW_TlsLib_SendAll(int sd,
                       void* pSecureSocketCtx,
                       uint8_t* pData,
                       size_t dataBytes);


//------------------------------------------------------------------------------
///
/// @brief Sends data securely until everything has been sent in a loop.
///
/// @param[in] sd Socket to send data on.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// CW_TlsLib_MakeSocketSecure().
///
/// @param[in] pData Pointer to buffer to send.
///
/// @param[in] dataBytes Size of the buffer to send in bytes.
///
//------------------------------------------------------------------------------
void CW_TlsLib_SendToAll(int sd,
                         void* pSecureSocketCtx,
                         uint32_t ip4Addr,
                         uint16_t port,
                         uint8_t* pData,
                         size_t dataBytes);


//------------------------------------------------------------------------------
///
/// @brief Sends data securely until everything has been sent in a loop but
/// byte by byte.
///
/// @param[in] sd Socket to send data on.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// CW_TlsLib_MakeSocketSecure().
///
/// @param[in] pData Pointer to buffer to send.
///
/// @param[in] dataBytes Size of the buffer to send in bytes.
///
//------------------------------------------------------------------------------
void CW_TlsLib_SendOneByOneByte(int sd,
                                void* pSecureSocketCtx,
                                uint8_t* pData,
                                size_t dataBytes);


//------------------------------------------------------------------------------
///
/// @brief Sends data securely at once. No loop involved.
///
/// @param[in] sd Socket to send data on.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// CW_TlsLib_MakeSocketSecure().
///
/// @param[in] pData Pointer to buffer to send.
///
/// @param[in] dataBytes Size of the buffer to send in bytes.
///
//------------------------------------------------------------------------------
void CW_TlsLib_SendAllInOne(int sd,
                            void* pSecureSocketCtx,
                            uint8_t* pData,
                            size_t dataBytes);


//-----------------------------------------------------------------------------
///
/// @brief Shut the security library down.
///
//-----------------------------------------------------------------------------
void CW_TlsLib_Shutdown(void);

int CW_TlsLib_Recv(int sd,
                   void* pSecureSocketCtx,
                   uint8_t* pData,
                   size_t dataBytes);

#endif // !defined(CW_TLSLIB_H)
