//==============================================================================
///
/// @file TlsLib.h
///
///
/// @brief TLS Lib abstraction api
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
#if !defined(TLSBM_TLSLIB_H)
#define TLSBM_TLSLIB_H

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
void TLSBM_TlsLib_Startup(void);


//------------------------------------------------------------------------------
///
/// @brief Creates a security context. Returns security context handle.
///
/// @return opaque handle of the security context.
///
//------------------------------------------------------------------------------
void* TLSBM_TlsLib_CreateSecurityContext(bool isServer,
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
/// TLSBM_TlsLib_CreateSecurityContext().
///
/// @return opaque handle of the secure sd context.
///
//------------------------------------------------------------------------------
void* TLSBM_TlsLib_MakeSocketSecure(int sd,
                                 void* pSecureCtx);

void* TLSBM_TlsLib_MakeDtlsSocketSecure(int* pSd,
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
/// TLSBM_TlsLib_MakeSocketSecure().
///
/// @return opaque handle of the secure sd context.
///
//------------------------------------------------------------------------------
void TLSBM_TlsLib_UnmakeSocketSecure(int sd, void* pSecureSocketCtx);


//------------------------------------------------------------------------------
///
/// @brief Destroys a security context.
///
/// @param[in] pSecureCtx Pointer to a security context.
///
/// @return opaque handle of the security context.
///
//------------------------------------------------------------------------------
void TLSBM_TlsLib_DestroySecureContext(void* pSecureCtx);


//------------------------------------------------------------------------------
///
/// @brief Performs client handshake.
///
/// Usually after connect.
///
/// @param[in] sd Socket to perform handshake on.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// TLSBM_TlsLib_MakeSocketSecure().
///
//------------------------------------------------------------------------------
void TLSBM_TlsLib_ClientHandshake(int sd, void* pSecureSocketCtx);


//------------------------------------------------------------------------------
///
/// @brief Performs server handshake.
///
/// Usually after accept.
///
/// @param[in] sd Socket to perform handshake on.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// TLSBM_TlsLib_MakeSocketSecure().
///
/// @retval 0 all ok
/// @retval -1 error
///
//------------------------------------------------------------------------------
int TLSBM_TlsLib_ServerHandshake(int sd, void* pSecureSocketCtx);

//------------------------------------------------------------------------------
///
/// @brief Sends data securely until everything has been sent in a loop.
///
/// @param[in] sd Socket to send data on.
///
/// @param[in] pSecureSocketCtx Pointer to secure sd context created by
/// TLSBM_TlsLib_MakeSocketSecure().
///
/// @param[in] pData Pointer to buffer to send.
///
/// @param[in] dataBytes Size of the buffer to send in bytes.
///
//------------------------------------------------------------------------------
void TLSBM_TlsLib_SendAll(int sd,
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
/// TLSBM_TlsLib_MakeSocketSecure().
///
/// @param[in] pData Pointer to buffer to send.
///
/// @param[in] dataBytes Size of the buffer to send in bytes.
///
//------------------------------------------------------------------------------
void TLSBM_TlsLib_SendToAll(int sd,
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
/// TLSBM_TlsLib_MakeSocketSecure().
///
/// @param[in] pData Pointer to buffer to send.
///
/// @param[in] dataBytes Size of the buffer to send in bytes.
///
//------------------------------------------------------------------------------
void TLSBM_TlsLib_SendOneByOneByte(int sd,
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
/// TLSBM_TlsLib_MakeSocketSecure().
///
/// @param[in] pData Pointer to buffer to send.
///
/// @param[in] dataBytes Size of the buffer to send in bytes.
///
//------------------------------------------------------------------------------
void TLSBM_TlsLib_SendAllInOne(int sd,
                            void* pSecureSocketCtx,
                            uint8_t* pData,
                            size_t dataBytes);


//-----------------------------------------------------------------------------
///
/// @brief Shut the security library down.
///
//-----------------------------------------------------------------------------
void TLSBM_TlsLib_Shutdown(void);

int TLSBM_TlsLib_Recv(int sd,
                   void* pSecureSocketCtx,
                   uint8_t* pData,
                   size_t dataBytes);


const char* TLSBM_TlsLib_GetName(void);

#endif // !defined(TLSBM_TLSLIB_H)
