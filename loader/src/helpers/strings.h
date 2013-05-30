/*
 * String helpers defenition
 */

#ifndef _STRINGS_HELPER_H_
#define _STRINGS_HELPER_H_

#include <Windows.h>

namespace Helpers
{

    DWORD strlenW(LPCWSTR lpString);
    DWORD strlenA(LPCSTR lpString);
    LPWSTR strcpyW(LPWSTR dest, LPCWSTR src);
    LPCWSTR ExtractFileName(LPCWSTR lpFilePath);
    LPWSTR ExtractFileDirectory(LPCWSTR lpFilePath, LPWSTR lpDirectory);
    int strcmpA(LPCSTR s1, LPCSTR s2);
    int stricmpA(LPCSTR s1, LPCSTR s2);

}

#endif // _STRINGS_HELPER_H_
