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

static FILE* cw_Common_heapCsv;

static uint8_t cw_Common_psk[] = {
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03,
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03,
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03,
                                'M', 'A', 'G', 'I', 'C', 0x01, 0x02, 0x03
};

static const char* cw_Common_pPskIdentity = "WIZZARD";

//-----------------------------------------------------------------------------
// Function definitions
//-----------------------------------------------------------------------------

void CW_Common_Startup(void)
{
    cw_Common_heapCsv = fopen("heap.csv", "w");
    if (cw_Common_heapCsv == NULL)
    {
        CW_Common_Die("unable to open heap.csv file for writing");
    }


    fwrite("op,ptr,orig_ptr,size_bytes\n",
           sizeof("op,ptr,orig_ptr,size_bytes\n") - 1, 1, cw_Common_heapCsv);
    fflush(cw_Common_heapCsv);
}


uint8_t* CW_Common_Allocacheck(size_t stackMaxBytes)
{
    uint8_t* pAlloca = alloca(stackMaxBytes);
    memset(pAlloca, 0xccU, stackMaxBytes);
    return pAlloca;
} // End: CW_Common_Allocacheck()

void CW_Common_Allocaprint(uint8_t* pAlloca,
                           size_t stackMaxBytes)
{
    size_t freeStack = 0;
    for (;
         freeStack < stackMaxBytes && pAlloca[freeStack] == 0xcc;
         freeStack++)
    {
        ; // just count
    }

    printf("Stack consumed %zu\n", stackMaxBytes-freeStack);
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
    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "M,0x%p,0x%p,%zu\n", pPtr, NULL, (size_t)size);
    if (wouldBeWritten > sizeof(buf))
    {
        CW_Common_Die("cannot write heap usage record line 4 malloc");
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

    size_t wouldBeWritten = snprintf(buf, sizeof(buf), "F,0x%p,0x%p,%zu\n", ptr, NULL, (size_t)0);
    if (wouldBeWritten > sizeof(buf))
    {
        CW_Common_Die("cannot write heap usage record line 4 free");
    }

    free(ptr);
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
