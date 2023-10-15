//==============================================================================
///
/// @file Common.c
///
///
/// @brief Common utils for wolf test.
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

//------------------------------------------------------------------------------
// Include files
//------------------------------------------------------------------------------
#include "include/tlsbm/Common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <malloc.h>


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

static uint8_t tlsbm_Common_canaries[] = {0xca, 0xfe, 0xba, 0xbe};

static FILE* tlsbm_Common_heapCsv;

static uint32_t tlsbm_Common_ip4Addr;

static uint16_t tlsbm_Common_port;

static uint8_t tlsbm_Common_psk[] = {
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03,
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03,
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03,
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03
};

static const char* tlsbm_Common_pPskIdentity = "WIZZARD";


static SuiteCfg_t tlsbm_Common_suiteCfgs[] = {
                                           {TLSBM_CIPHER_SUITE_ECC_CERT, true},
                                           {TLSBM_CIPHER_SUITE_ECC_PSK, true},
                                           {TLSBM_CIPHER_SUITE_RSA_CERT, false},
                                           {TLSBM_CIPHER_SUITE_RSA_PSK, false},
                                           {TLSBM_CIPHER_SUITE_ECC_CERT_GCM,true},
                                           {TLSBM_CIPHER_SUITE_ECC_PSK_NULL,true},
                                           {TLSBM_CIPHER_SUITE_ECC_CHACHA20_POLY1305,true},
};

//-----------------------------------------------------------------------------
// Function definitions
//-----------------------------------------------------------------------------

void TLSBM_Common_Startup(const char* pMethodName, const char* pTlsLibName)
{
    char filename[64];
    size_t wouldBeWritten = snprintf(filename,
                                     sizeof(filename),
                                     "%s_%s.csv",
                                     pMethodName,
                                     pTlsLibName);
    if (wouldBeWritten > sizeof(filename))
    {
        TLSBM_Common_Die("cannot write heap usage record line 4 malloc");
    }

    tlsbm_Common_heapCsv = fopen(filename, "w");
    if (tlsbm_Common_heapCsv == NULL)
    {
        TLSBM_Common_Die("unable to open .csv file for writing");
    }


    fwrite("op,ptr,orig_ptr,size_bytes\n",
           sizeof("op,ptr,orig_ptr,size_bytes\n") - 1, 1, tlsbm_Common_heapCsv);
    fflush(tlsbm_Common_heapCsv);
}


void* TLSBM_Common_Allocacheck(void)
{
    uint8_t* pAlloca = alloca(ALLOCACHECK_STACK_BYTES);

    size_t i = 0;
    for (; i < ALLOCACHECK_STACK_BYTES; i++)
    {
        pAlloca[i] = tlsbm_Common_canaries[i%4];
    }

// #if defined(TLSBM_ENV_DEBUG_ENABLE)
    printf("Filling in %zu bytes of stack with 0x%02x 0x%02x 0x%02x 0x%02x\n",
           i,
           tlsbm_Common_canaries[0],
           tlsbm_Common_canaries[1],
           tlsbm_Common_canaries[2],
           tlsbm_Common_canaries[3]);
// #endif // defined(TLSBM_ENV_DEBUG_ENABLE)

    return pAlloca;
} // End: TLSBM_Common_Allocacheck()

void TLSBM_Common_Allocaprint(void* pAllocaHint)
{
#ifdef _WIN32
    uint8_t* pAlloca = pAllocaHint;
#else
    uint8_t* pAlloca = alloca(ALLOCACHECK_STACK_BYTES);
#endif


    size_t i = 0;
    while (i < ALLOCACHECK_STACK_BYTES - 4)
    {
        if (pAlloca[i] == tlsbm_Common_canaries[0]
            && pAlloca[i + 1] == tlsbm_Common_canaries[1]
            && pAlloca[i + 2] == tlsbm_Common_canaries[2]
            && pAlloca[i + 3] == tlsbm_Common_canaries[3])
        {
            break;
        }

        i++;
    }

// #if defined(TLSBM_ENV_DEBUG_ENABLE)
    printf("running %zu positions\n", i);
// #endif // defined(TLSBM_ENV_DEBUG_ENABLE)
    pAlloca = &pAlloca[i];

    size_t freeStack = 0;
    bool ok = true;
    while(true)
    {
        if (pAlloca[freeStack] != tlsbm_Common_canaries[freeStack%4])
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
        TLSBM_Common_Die("cannot write stack usage record line");
    }

//#if defined(TLSBM_ENV_DEBUG_ENABLE)
    printf("%zu\n", ALLOCACHECK_STACK_BYTES-freeStack);
//#endif // defined(TLSBM_ENV_DEBUG_ENABLE)


    fwrite(buf, wouldBeWritten, 1, tlsbm_Common_heapCsv);
    fflush(tlsbm_Common_heapCsv);
} // End: TLSBM_Common_Allocaprint()

//-----------------------------------------------------------------------------
///
/// @brief Dies with a message.
///
/// @param[in] pErrorMsg - error message
///
//-----------------------------------------------------------------------------
void TLSBM_Common_Die(const char* pErrorMsg)
{
    perror(pErrorMsg);
    exit(1);
} // End: TLSBM_Common_Die()

void* TLSBM_Common_Malloc(unsigned long size)
{
    char buf[64];

    void* pPtr = malloc(size);
    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "M,0x%p,0x0,%zu\n", pPtr, (size_t)size);
    if (wouldBeWritten > sizeof(buf))
    {
        TLSBM_Common_Die("cannot write heap usage record line 4 malloc");
    }

#if defined(TLSBM_ENV_DEBUG_ENABLE)
    if (size > 512)
    {
        printf("Allocating %zuB\n", size);
    }
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)

    fwrite(buf, wouldBeWritten, 1, tlsbm_Common_heapCsv);
    fflush(tlsbm_Common_heapCsv);

    return pPtr;
}

void* TLSBM_Common_Calloc(size_t nitems, size_t itemBytes)
{
    size_t size = nitems * itemBytes;
    char buf[64];

    void* pPtr = calloc(nitems, itemBytes);
    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "M,0x%p,0x0,%zu\n", pPtr, size);
    if (wouldBeWritten > sizeof(buf))
    {
        TLSBM_Common_Die("cannot write heap usage record line 4 calloc");
    }

#if defined(TLSBM_ENV_DEBUG_ENABLE)
    if (size > 512)
    {
        printf("Allocating %zuB\n", size);
    }
#endif // defined(TLSBM_ENV_DEBUG_ENABLE)

    fwrite(buf, wouldBeWritten, 1, tlsbm_Common_heapCsv);
    fflush(tlsbm_Common_heapCsv);

    return pPtr;
}

void* TLSBM_Common_Realloc(void* ptr, unsigned long size)
{
    char buf[64];

    void* pPtr = realloc(ptr, size);
    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "R,0x%p,0x%p,%zu\n", pPtr, ptr, (size_t)size);
    if (wouldBeWritten > sizeof(buf))
    {
        TLSBM_Common_Die("cannot write heap usage record line 4 realloc");
    }

    fwrite(buf, wouldBeWritten, 1, tlsbm_Common_heapCsv);
    fflush(tlsbm_Common_heapCsv);

    return pPtr;
}

void  TLSBM_Common_Free(void* ptr)
{
    if (ptr == NULL)
    {
        return;
    }

    char buf[64];

    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "F,0x%p,0x0,0\n", ptr);
    if (wouldBeWritten > sizeof(buf))
    {
        TLSBM_Common_Die("cannot write heap usage record line 4 free");
    }

    free(ptr);
    fwrite(buf, wouldBeWritten, 1, tlsbm_Common_heapCsv);
    fflush(tlsbm_Common_heapCsv);
}

void  TLSBM_Common_AllocLogMarkerBegin(const char* pMarker)
{
    char buf[128];

    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "B,%s,,\n", pMarker);
    if (wouldBeWritten > sizeof(buf))
    {
        TLSBM_Common_Die("cannot write heap usage begin marker");
    }

    fwrite(buf, wouldBeWritten, 1, tlsbm_Common_heapCsv);
    fflush(tlsbm_Common_heapCsv);
}

void  TLSBM_Common_AllocLogMarkerEnd(const char* pMarker)
{
    char buf[128];

    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "E,%s,,\n", pMarker);
    if (wouldBeWritten > sizeof(buf))
    {
        TLSBM_Common_Die("cannot write heap usage end marker");
    }

    fwrite(buf, wouldBeWritten, 1, tlsbm_Common_heapCsv);
    fflush(tlsbm_Common_heapCsv);
}


const char* TLSBM_Common_GetPskIdentity(void)
{
    return tlsbm_Common_pPskIdentity;
}

uint8_t* TLSBM_Common_GetPsk(size_t* pPskBytes)
{
    *pPskBytes = sizeof(tlsbm_Common_psk);
    return tlsbm_Common_psk;
}

void TLSBM_Common_Shutdown(void)
{
    fflush(tlsbm_Common_heapCsv);
    fclose(tlsbm_Common_heapCsv);
}


SuiteCfg_t* TLSBM_Common_GetSuiteCfg(int id)
{
    return (id < (sizeof(tlsbm_Common_suiteCfgs) / sizeof(SuiteCfg_t))) ? &tlsbm_Common_suiteCfgs[id] : NULL;
}


void TLSBM_Common_SetIp4Port(uint32_t ip4Addr, uint16_t port)
{
    tlsbm_Common_ip4Addr = ip4Addr;
    tlsbm_Common_port = port;
}


void TLSBM_Common_GetIp4Port(uint32_t* pIp4Addr, uint16_t* pPort)
{
    *pIp4Addr = tlsbm_Common_ip4Addr;
    *pPort = tlsbm_Common_port;
}
