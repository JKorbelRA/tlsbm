//==============================================================================
///
/// @file Common.c
///
///
/// @brief Common utils for wolf test.
///
/// Copyright (c) 2022 Rockwell Automation Technologies, Inc.
/// All rights reserved.
//==============================================================================

//------------------------------------------------------------------------------
// Include files
//------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <malloc.h>

#include <crazywolf/Common.h>

//-----------------------------------------------------------------------------
// Constants
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Macros
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
// Local data types
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Local constants
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Global references
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Forward function declarations
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Variable definitions
//-----------------------------------------------------------------------------

static uint8_t cw_Common_canaries[] = {0xca, 0xfe, 0xba, 0xbe};

static FILE* cw_Common_heapCsv;

static uint32_t cw_Common_ip4Addr;

static uint16_t cw_Common_port;

static uint8_t cw_Common_psk[] = {
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03,
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03,
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03,
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03
};

static const char* cw_Common_pPskIdentity = "WIZZARD";


static SuiteCfg_t cw_Common_suiteCfgs[] = {
                                           {CW_CIPHER_SUITE_ECC_CERT,
                                            CW_CACERT_ECC_PATH,
                                            CW_DEVCERT_ECC_PATH,
                                            CW_DEVKEY_ECC_PATH},
                                           {CW_CIPHER_SUITE_ECC_PSK,
                                            CW_CACERT_ECC_PATH,
                                            CW_DEVCERT_ECC_PATH,
                                            CW_DEVKEY_ECC_PATH},
                                           {CW_CIPHER_SUITE_RSA_CERT,
                                            CW_CACERT_RSA_PATH,
                                            CW_DEVCERT_RSA_PATH,
                                            CW_DEVKEY_RSA_PATH},
                                            {CW_CIPHER_SUITE_RSA_PSK,
                                             CW_CACERT_RSA_PATH,
                                             CW_DEVCERT_RSA_PATH,
                                             CW_DEVKEY_RSA_PATH},
                                             {CW_CIPHER_SUITE_ECC_CERT_GCM,
                                              CW_CACERT_ECC_PATH,
                                              CW_DEVCERT_ECC_PATH,
                                              CW_DEVKEY_ECC_PATH}
};

//-----------------------------------------------------------------------------
// Function definitions
//-----------------------------------------------------------------------------

void CW_Common_Startup(const char* pMethodName, const char* pTlsLibName)
{
    char filename[64];
    size_t wouldBeWritten = snprintf(filename,
                                     sizeof(filename),
                                     "%s_%s.csv",
                                     pMethodName,
                                     pTlsLibName);
    if (wouldBeWritten > sizeof(filename))
    {
        CW_Common_Die("cannot write heap usage record line 4 malloc");
    }

    cw_Common_heapCsv = fopen(filename, "w");
    if (cw_Common_heapCsv == NULL)
    {
        CW_Common_Die("unable to open .csv file for writing");
    }


    fwrite("op,ptr,orig_ptr,size_bytes\n",
           sizeof("op,ptr,orig_ptr,size_bytes\n") - 1, 1, cw_Common_heapCsv);
    fflush(cw_Common_heapCsv);
}


void* CW_Common_Allocacheck(void)
{
    uint8_t* pAlloca = alloca(ALLOCACHECK_STACK_BYTES);

    size_t i = 0;
    for (; i < ALLOCACHECK_STACK_BYTES; i++)
    {
        pAlloca[i] = cw_Common_canaries[i%4];
    }

    printf("Filling in %zu bytes of stack with 0x%02x 0x%02x 0x%02x 0x%02x\n",
           i,
           cw_Common_canaries[0],
           cw_Common_canaries[1],
           cw_Common_canaries[2],
           cw_Common_canaries[3]);

    return pAlloca;
} // End: CW_Common_Allocacheck()

void CW_Common_Allocaprint(void* pAllocaHint)
{
#ifdef _WIN32
    uint8_t* pAlloca = pAllocaHint;
#else
    uint8_t* pAlloca = alloca(ALLOCACHECK_STACK_BYTES);
#endif


    size_t i = 0;
    while (i < ALLOCACHECK_STACK_BYTES - 4)
    {
        if (pAlloca[i] == cw_Common_canaries[0]
            && pAlloca[i + 1] == cw_Common_canaries[1]
            && pAlloca[i + 2] == cw_Common_canaries[2]
            && pAlloca[i + 3] == cw_Common_canaries[3])
        {
            break;
        }

        i++;
    }

    printf("running %zu positions\n", i);
    pAlloca = &pAlloca[i];

    size_t freeStack = 0;
    bool ok = true;
    while(true)
    {
        if (pAlloca[freeStack] != cw_Common_canaries[freeStack%4])
        {
            break;
        }

        freeStack++;
    }

    char buf[64];
    size_t wouldBeWritten = snprintf(buf,
                                     sizeof(buf),
                                     "S,0x%p,%zu,%zu\n",
                                     pAlloca,
                                     (size_t)ALLOCACHECK_STACK_BYTES,
                                     (size_t)ALLOCACHECK_STACK_BYTES-freeStack);
    if (wouldBeWritten > sizeof(buf))
    {
        CW_Common_Die("cannot write stack usage record line");
    }

    printf("%zu\n", ALLOCACHECK_STACK_BYTES-freeStack);


    fwrite(buf, wouldBeWritten, 1, cw_Common_heapCsv);
    fflush(cw_Common_heapCsv);
} // End: CW_Common_Allocaprint()

//-----------------------------------------------------------------------------
///
/// @brief Dies with a message.
///
/// @param[in] pErrorMsg - error message
///
//-----------------------------------------------------------------------------
void CW_Common_Die(const char* pErrorMsg)
{
    perror(pErrorMsg);
    exit(1);
} // End: CW_Common_Die()

void* CW_Common_Malloc(unsigned long size)
{
    char buf[64];

    void* pPtr = malloc(size);
    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "M,0x%p,0x0,%zu\n", pPtr, (size_t)size);
    if (wouldBeWritten > sizeof(buf))
    {
        CW_Common_Die("cannot write heap usage record line 4 malloc");
    }

#if defined(CW_ENV_DEBUG_ENABLE)
    if (size > 512)
    {
        printf("Allocating %zuB\n", size);
    }
#endif // defined(CW_ENV_DEBUG_ENABLE)

    fwrite(buf, wouldBeWritten, 1, cw_Common_heapCsv);
    fflush(cw_Common_heapCsv);

    return pPtr;
}

void* CW_Common_Calloc(size_t nitems, size_t itemBytes)
{
    size_t size = nitems * itemBytes;
    char buf[64];

    void* pPtr = calloc(nitems, itemBytes);
    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "M,0x%p,0x0,%zu\n", pPtr, size);
    if (wouldBeWritten > sizeof(buf))
    {
        CW_Common_Die("cannot write heap usage record line 4 calloc");
    }

    if (size > 512)
    {
        printf("Allocating %zuB\n", size);
    }

    fwrite(buf, wouldBeWritten, 1, cw_Common_heapCsv);
    fflush(cw_Common_heapCsv);

    return pPtr;
}

void* CW_Common_Realloc(void* ptr, unsigned long size)
{
    char buf[64];

    void* pPtr = realloc(ptr, size);
    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "R,0x%p,0x%p,%zu\n", pPtr, ptr, (size_t)size);
    if (wouldBeWritten > sizeof(buf))
    {
        CW_Common_Die("cannot write heap usage record line 4 realloc");
    }

    fwrite(buf, wouldBeWritten, 1, cw_Common_heapCsv);
    fflush(cw_Common_heapCsv);

    return pPtr;
}

void  CW_Common_Free(void* ptr)
{
    if (ptr == NULL)
    {
        return;
    }

    char buf[64];

    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "F,0x%p,0x0,0\n", ptr);
    if (wouldBeWritten > sizeof(buf))
    {
        CW_Common_Die("cannot write heap usage record line 4 free");
    }

    free(ptr);
    fwrite(buf, wouldBeWritten, 1, cw_Common_heapCsv);
    fflush(cw_Common_heapCsv);
}

void  CW_Common_AllocLogMarkerBegin(const char* pMarker)
{
    char buf[128];

    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "B,%s,,\n", pMarker);
    if (wouldBeWritten > sizeof(buf))
    {
        CW_Common_Die("cannot write heap usage begin marker");
    }

    fwrite(buf, wouldBeWritten, 1, cw_Common_heapCsv);
    fflush(cw_Common_heapCsv);
}

void  CW_Common_AllocLogMarkerEnd(const char* pMarker)
{
    char buf[128];

    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "E,%s,,\n", pMarker);
    if (wouldBeWritten > sizeof(buf))
    {
        CW_Common_Die("cannot write heap usage end marker");
    }

    fwrite(buf, wouldBeWritten, 1, cw_Common_heapCsv);
    fflush(cw_Common_heapCsv);
}


const char* CW_Common_GetPskIdentity(void)
{
    return cw_Common_pPskIdentity;
}

uint8_t* CW_Common_GetPsk(size_t* pPskBytes)
{
    *pPskBytes = sizeof(cw_Common_psk);
    return cw_Common_psk;
}

void CW_Common_Shutdown(void)
{
    fflush(cw_Common_heapCsv);
    fclose(cw_Common_heapCsv);
}


SuiteCfg_t* CW_Common_GetCipherSuiteAndFiles(bool isPsk, bool isRsa, bool isGcm)
{
    int id = ((isRsa == true) << 1) | (isPsk == true);

    if (isGcm)
    {
        id = 4;
    }

    return &cw_Common_suiteCfgs[id];
}


void CW_Common_SetIp4Port(uint32_t ip4Addr, uint16_t port)
{
    cw_Common_ip4Addr = ip4Addr;
    cw_Common_port = port;
}


void CW_Common_GetIp4Port(uint32_t* pIp4Addr, uint16_t* pPort)
{
    *pIp4Addr = cw_Common_ip4Addr;
    *pPort = cw_Common_port;
}
