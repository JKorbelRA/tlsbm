//==============================================================================
///
/// @file Platform.h
///
///
/// @brief Platform abstraction api
///
/// Copyright (c) 2023 Rockwell Automation Technologies, Inc.
/// All rights reserved.
//==============================================================================
#if !defined(CW_PLATFORM_H)
#define CW_PLATFORM_H


#include <stdbool.h>
#include <stdint.h>


//-----------------------------------------------------------------------------
///
/// @brief Init platform.
///
//-----------------------------------------------------------------------------
void CW_Platform_Startup(void);


//-----------------------------------------------------------------------------
///
/// @brief Shut the platform down.
///
//-----------------------------------------------------------------------------
void CW_Platform_Shutdown(void);

#endif // !defined(CW_PLATFORM_H)
