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

#ifndef WOLF_USER_SETTINGS_H
#define WOLF_USER_SETTINGS_H


#define XMALLOC_USER
#undef NO_PSK

#undef ALT_ECC_SIZE
//#define USE_SLOW_SHA2
//#define USE_SLOW_SHA
//#define GCM_SMALL
#define NO_OLD_TLS
#define RSA_LOW_MEM
//#define ECC_LOW_MEM
#define CURVE25519_SMALL
#define WOLFSSL_SMALL_CERT_VERIFY
#define NO_OLD_POLY1305
#define NO_SESSION_CACHE
#undef WOLFSSL_SMALL_STACK

#define WOLFSSL_SP_NO_MALLOC

#define CURVE25519_SMALL
#define CURVED25519_SMALL
#define ED25519_SMALL

#define NO_ERROR_STRINGS
// #define NO_MD4
#define NO_MD5
#define NO_SHA
// #define NO_RC4
#define HAVE_NULL_CIPHER
#define SINGLE_THREADED
#undef ECC_SHAMIR

#define WOLFSSL_SP_MATH
#undef WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL
#define WOLFSSL_SP_NO_MALLOC
#define WOLFSSL_SP_NO_DYN_STACK
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_DH

#undef WOLFSSL_HAVE_CERT_SERVICE
// #define NO_DSA
// #define NO_DH
#undef NO_WOLFSSL_CLIENT
#undef WOLFSSL_TLS13
#undef WC_RSA_PSS

#define WOLFSSL_SP_ECC_384
#define WOLFSSL_SP_ECC_521

#define WOLFSSL_SP_384
#define HAVE_ECC384

#define WOLFSSL_SP_521
#define HAVE_ECC521

#undef WOLFSSL_SP_4096

#define WC_ASN_NAME_MAX 128
#define WC_CTC_MAX_ALT_SIZE 128
#undef SESSION_CERTS
#undef HAVE_SESSION_TICKET
#undef OPENSSL_EXTRA
#undef OPENSSL_ALL

#endif // WOLF_USER_SETTINGS_H
