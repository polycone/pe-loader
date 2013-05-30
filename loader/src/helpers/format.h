/*
 * String formatting helpers defenition
 */

#ifndef _FORMAT_HELPER_H_
#define _FORMAT_HELPER_H_

#include <Windows.h>

namespace Helpers
{

    typedef enum
    {
        WPR_UNKNOWN,
        WPR_CHAR,
        WPR_WCHAR,
        WPR_STRING,
        WPR_WSTRING,
        WPR_SIGNED,
        WPR_UNSIGNED,
        WPR_HEXA
    } WPRINTF_TYPE;

    typedef struct
    {
        UINT flags;
        UINT width;
        UINT precision;
        WPRINTF_TYPE type;
    } WPRINTF_FORMAT;

    typedef union {
        WCHAR wchar_view;
        CHAR char_view;
        LPCSTR lpcstr_view;
        LPCWSTR lpcwstr_view;
        LONGLONG int_view;
    } WPRINTF_DATA;

    #define WPRINTF_LEFTALIGN   0x0001  /* Align output on the left ('-' prefix) */
    #define WPRINTF_PREFIX_HEX  0x0002  /* Prefix hex with 0x ('#' prefix) */
    #define WPRINTF_ZEROPAD     0x0004  /* Pad with zeros ('0' prefix) */
    #define WPRINTF_LONG        0x0008  /* Long arg ('l' prefix) */
    #define WPRINTF_SHORT       0x0010  /* Short arg ('h' prefix) */
    #define WPRINTF_UPPER_HEX   0x0020  /* Upper-case hex ('X' specifier) */
    #define WPRINTF_WIDE        0x0040  /* Wide arg ('w' prefix) */
    #define WPRINTF_INTPTR      0x0080  /* Pointer-size arg ('I' prefix) */
    #define WPRINTF_I64         0x0100  /* 64-bit arg ('I64' prefix) */

    INT WINAPI wvsprintfW( LPWSTR buffer, LPCWSTR spec, va_list args );

}

#endif // _FORMAT_HELPER_H_
