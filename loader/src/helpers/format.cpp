/*
 * wvsprintfW helper
 * This file use a part of dlls/shlwapi/wsprintf.c from Wine project
 * (http://sourceforge.net/projects/wine/files/Source/)
 */

/*
 * wsprintf functions
 *
 * Copyright 1996 Alexandre Julliard
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
 *
 */

#include "../system/syscalls.h"
#include "format.h"

namespace Helpers
{

    static const CHAR null_stringA[] = "(null)";
    static const WCHAR null_stringW[] = { '(', 'n', 'u', 'l', 'l', ')', 0 };

    INT WPRINTF_ParseFormatW( LPCWSTR format, WPRINTF_FORMAT *res )
    {
        LPCWSTR p = format;

        res->flags = 0;
        res->width = 0;
        res->precision = 0;
        if (*p == '-') { res->flags |= WPRINTF_LEFTALIGN; p++; }
        if (*p == '#') { res->flags |= WPRINTF_PREFIX_HEX; p++; }
        if (*p == '0') { res->flags |= WPRINTF_ZEROPAD; p++; }
        while ((*p >= '0') && (*p <= '9'))  /* width field */
        {
            res->width = res->width * 10 + *p - '0';
            p++;
        }
        if (*p == '.')  /* precision field */
        {
            p++;
            while ((*p >= '0') && (*p <= '9'))
            {
                res->precision = res->precision * 10 + *p - '0';
                p++;
            }
        }
        if (*p == 'l') { res->flags |= WPRINTF_LONG; p++; }
        else if (*p == 'h') { res->flags |= WPRINTF_SHORT; p++; }
        else if (*p == 'w') { res->flags |= WPRINTF_WIDE; p++; }
        else if (*p == 'I')
        {
            if (p[1] == '6' && p[2] == '4') { res->flags |= WPRINTF_I64; p += 3; }
            else if (p[1] == '3' && p[2] == '2') p += 3;
            else { res->flags |= WPRINTF_INTPTR; p++; }
        }
        switch(*p)
        {
        case 'c':
            res->type = (res->flags & WPRINTF_SHORT) ? WPR_CHAR : WPR_WCHAR;
            break;
        case 'C':
            res->type = (res->flags & WPRINTF_LONG) ? WPR_WCHAR : WPR_CHAR;
            break;
        case 'd':
        case 'i':
            res->type = WPR_SIGNED;
            break;
        case 's':
            res->type = ((res->flags & WPRINTF_SHORT) && !(res->flags & WPRINTF_WIDE)) ? WPR_STRING : WPR_WSTRING;
            break;
        case 'S':
            res->type = (res->flags & (WPRINTF_LONG|WPRINTF_WIDE)) ? WPR_WSTRING : WPR_STRING;
            break;
        case 'u':
            res->type = WPR_UNSIGNED;
            break;
        case 'p':
            res->width = 2 * sizeof(void *);
            res->flags |= WPRINTF_ZEROPAD | WPRINTF_INTPTR;
            /* fall through */
        case 'X':
            res->flags |= WPRINTF_UPPER_HEX;
            /* fall through */
        case 'x':
            res->type = WPR_HEXA;
            break;
        default:
            res->type = WPR_UNKNOWN;
            p--;  /* print format as normal char */
            break;
        }
        return (INT)(p - format) + 1;
    }

    UINT WPRINTF_GetLen( WPRINTF_FORMAT *format, WPRINTF_DATA *arg,
                                  LPSTR number, UINT maxlen )
    {
        UINT len;

        if (format->flags & WPRINTF_LEFTALIGN) format->flags &= ~WPRINTF_ZEROPAD;
        if (format->width > maxlen) format->width = maxlen;
        switch(format->type)
        {
        case WPR_CHAR:
        case WPR_WCHAR:
            return (format->precision = 1);
        case WPR_STRING:
            if (!arg->lpcstr_view) arg->lpcstr_view = null_stringA;
            for (len = 0; !format->precision || (len < format->precision); len++)
                if (!*(arg->lpcstr_view + len)) break;
            if (len > maxlen) len = maxlen;
            return (format->precision = len);
        case WPR_WSTRING:
            if (!arg->lpcwstr_view) arg->lpcwstr_view = null_stringW;
            for (len = 0; !format->precision || (len < format->precision); len++)
                if (!*(arg->lpcwstr_view + len)) break;
            if (len > maxlen) len = maxlen;
            return (format->precision = len);
        case WPR_SIGNED:
        case WPR_UNSIGNED:
        case WPR_HEXA:
        {
            const char *digits = (format->flags & WPRINTF_UPPER_HEX) ? "0123456789ABCDEF" : "0123456789abcdef";
            ULONGLONG num = arg->int_view;
            int base = format->type == WPR_HEXA ? 16 : 10;
            char buffer[20], *p = buffer, *dst = number;

            if (format->type == WPR_SIGNED && arg->int_view < 0)
            {
                *dst++ = '-';
                num = -arg->int_view;
            }
            if (format->flags & WPRINTF_INTPTR) num = (UINT_PTR)num;
            else if (!(format->flags & WPRINTF_I64)) num = (UINT)num;

            do
            {
                *p++ = digits[num % base];
                num /= base;
            } while (num);
            while (p > buffer) *dst++ = *(--p);
            *dst = 0;
            len = dst - number;
            break;
        }
        default:
            return 0;
        }
        if (len > maxlen) len = maxlen;
        if (format->precision < len) format->precision = len;
        if (format->precision > maxlen) format->precision = maxlen;
        if ((format->flags & WPRINTF_ZEROPAD) && (format->width > format->precision))
            format->precision = format->width;
        if (format->flags & WPRINTF_PREFIX_HEX) len += 2;
        return len;
    }

    INT wvsnprintfW( LPWSTR buffer, UINT maxlen, LPCWSTR spec, va_list args )
    {
        WPRINTF_FORMAT format;
        LPWSTR p = buffer;
        UINT i, len, sign;
        CHAR number[21]; /* 64bit number can be 18446744073709551616 which is 20 chars. and a \0 */
        WPRINTF_DATA argData;

        while (*spec && (maxlen > 1))
        {
            if (*spec != '%') { *p++ = *spec++; maxlen--; continue; }
            spec++;
            if (*spec == '%') { *p++ = *spec++; maxlen--; continue; }
            spec += WPRINTF_ParseFormatW( spec, &format );

            switch(format.type)
            {
            case WPR_WCHAR:
                argData.wchar_view = (WCHAR)va_arg( args, int );
                break;
            case WPR_CHAR:
                argData.char_view = (CHAR)va_arg( args, int );
                break;
            case WPR_STRING:
                argData.lpcstr_view = va_arg( args, LPCSTR );
                break;
            case WPR_WSTRING:
                argData.lpcwstr_view = va_arg( args, LPCWSTR );
                break;
            case WPR_HEXA:
            case WPR_SIGNED:
            case WPR_UNSIGNED:
                if (format.flags & WPRINTF_INTPTR) argData.int_view = va_arg(args, INT_PTR);
                else if (format.flags & WPRINTF_I64) argData.int_view = va_arg(args, LONGLONG);
                else argData.int_view = va_arg(args, INT);
                break;
            default:
                argData.wchar_view = 0;
                break;
            }

            len = WPRINTF_GetLen( &format, &argData, number, maxlen - 1 );
            sign = 0;
            if (!(format.flags & WPRINTF_LEFTALIGN))
                for (i = format.precision; i < format.width; i++, maxlen--)
                    *p++ = ' ';
            switch(format.type)
            {
            case WPR_WCHAR:
                *p++ = argData.wchar_view;
                break;
            case WPR_CHAR:
                *p++ = argData.char_view;
                break;
            case WPR_STRING:
                {
                    LPCSTR ptr = argData.lpcstr_view;
                    for (i = 0; i < len; i++) *p++ = (BYTE)*ptr++;
                }
                break;
            case WPR_WSTRING:
                if (len) memcpy( p, argData.lpcwstr_view, len * sizeof(WCHAR) );
                p += len;
                break;
            case WPR_HEXA:
                if ((format.flags & WPRINTF_PREFIX_HEX) && (maxlen > 3))
                {
                    *p++ = '0';
                    *p++ = (format.flags & WPRINTF_UPPER_HEX) ? 'X' : 'x';
                    maxlen -= 2;
                    len -= 2;
                }
                /* fall through */
            case WPR_SIGNED:
                /* Transfer the sign now, just in case it will be zero-padded*/
                if (number[0] == '-')
                {
                    *p++ = '-';
                    sign = 1;
                }
                /* fall through */
            case WPR_UNSIGNED:
                for (i = len; i < format.precision; i++, maxlen--) *p++ = '0';
                for (i = sign; i < len; i++) *p++ = (BYTE)number[i];
                break;
            case WPR_UNKNOWN:
                continue;
            }
            if (format.flags & WPRINTF_LEFTALIGN)
                for (i = format.precision; i < format.width; i++, maxlen--)
                    *p++ = ' ';
            maxlen -= len;
        }
        *p = 0;
        return (maxlen > 1) ? (INT)(p - buffer) : -1;
    }

    INT WINAPI wvsprintfW( LPWSTR buffer, LPCWSTR spec, va_list args )
    {
        INT res = wvsnprintfW( buffer, 1024, spec, args );
        return ( res == -1 ) ? 1024 : res;
    }

} // namespace Helpers