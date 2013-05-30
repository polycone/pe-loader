/*
 * String resource helper
 * This file use a part of dlls/user32/resource.c from Wine project
 * (http://sourceforge.net/projects/wine/files/Source/)
 */

/*
 * USER resource functions
 *
 * Copyright 1993 Robert J. Amstadt
 * Copyright 1995, 2009 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "string_resource.h"
#include "../system/syscalls.h"

namespace Helpers
{

    int WINAPI LoadStringW(HINSTANCE instance, UINT resource_id, LPWSTR buffer, INT buflen)
    {
        HGLOBAL hmem;
        HRSRC hrsrc;
        WCHAR *p;
        int string_num;
        int i;

        if(buffer == NULL)
            return 0;

        /* Use loword (incremented by 1) as resourceid */
        hrsrc = FindResourceW(instance, MAKEINTRESOURCEW((LOWORD(resource_id) >> 4) + 1), (LPWSTR)RT_STRING);
        if (!hrsrc) 
            return 0;
        hmem = LoadResource(instance, hrsrc);
        if (!hmem) 
            return 0;

        p = (PWCHAR)LockResource(hmem);
        string_num = resource_id & 0x000f;
        for (i = 0; i < string_num; i++)
        p += *p + 1;

        /*if buflen == 0, then return a read-only pointer to the resource itself in buffer
        it is assumed that buffer is actually a (LPWSTR *) */
        if(buflen == 0)
        {
            *((LPWSTR *)buffer) = p + 1;
            return *p;
        }

        i = min(buflen - 1, *p);
        if (i > 0) 
        {
            memcpy(buffer, p + 1, i * sizeof (WCHAR));
            buffer[i] = 0;
        } 
        else if (buflen > 1)
        {
            buffer[0] = 0;
            return 0;
        }
    
        return i;
    }

} // namespace Helpers
