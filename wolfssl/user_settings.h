/* settings.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 *   ************************************************************************
 *
 *   ******************************** NOTICE ********************************
 *
 *   ************************************************************************
 *
 *   This method of uncommenting a line in settings.h is outdated.
 *
 *   Please use user_settings.h / WOLFSSL_USER_SETTINGS
 *
 *         or
 *
 *   ./configure CFLAGS="-DFLAG"
 *
 *   For more information see:
 *
 *   https://www.wolfssl.com/how-do-i-manage-the-build-configuration-of-wolfssl/
 *
 */


/* Place OS specific preprocessor flags, defines, includes here, will be
   included into every file because types.h includes it */


#ifndef WOLF_CRYPT_USER_SETTINGS_H
#define WOLF_CRYPT_USER_SETTINGS_H

#ifdef __cplusplus
    extern "C" {
#endif

#define XMALLOC_OVERRIDE

    extern void* CW_Common_Malloc(unsigned long size, void* heap, int type);
    extern void* CW_Common_Realloc(void* ptr, unsigned long size, void* heap,
                                 int type);
    extern void  CW_Common_Free(void* ptr, void* heap, int type);

    #define XMALLOC(s, h, type)  CW_Common_Malloc((s), (h), (type))
    #define XREALLOC(p, n, h, t) CW_Common_Realloc((p), (n), (h), (t))
    #define XFREE(p, h, type)    CW_Common_Free((p), (h), (type))


#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif
