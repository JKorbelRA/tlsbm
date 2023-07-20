#ifndef WOLF_USER_SETTINGS_H
#define WOLF_USER_SETTINGS_H


#define XMALLOC_USER
#undef NO_PSK

#undef ALT_ECC_SIZE
#define SMALL_SESSION_CACHE
#define USE_SLOW_SHA2
#define GCM_SMALL
#define NO_OLD_TLS
#define RSA_LOW_MEM
#define CURVE25519_SMALL
#define WOLFSSL_SMALL_CERT_VERIFY
// #define HAVE_CHACHA
// #define HAVE_POLY1305
#define NO_OLD_POLY1305


#endif // WOLF_USER_SETTINGS_H
