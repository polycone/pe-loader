/*
 * Strings helper functions
 */

#include "../system/syscalls.h"
#include "../system/system.h"
#include "strings.h"

namespace Helpers
{

    DWORD strlenW(LPCWSTR lpString)
    {
        PCWCHAR pLetter = lpString;
        DWORD dwLength = 0;
        while (*pLetter++ != 0)
            ++dwLength;
        return dwLength;
    }

    DWORD strlenA(LPCSTR lpString)
    {
        PCCH pLetter = lpString;
        DWORD dwLength = 0;
        while (*pLetter++ != 0)
            ++dwLength;
        return dwLength;
    }

    LPWSTR strcpyW(LPWSTR dest, LPCWSTR src)
    {
        memcpy(dest, src, (strlenW(src) + 1) * sizeof(WCHAR));
        return dest;
    }

    int strcmpA(LPCSTR s1, LPCSTR s2)
    {
        DWORD dwLen1 = strlenA(s1);
        DWORD dwLen2 = strlenA(s2);
        if (dwLen1 != dwLen2)
            return -1;
        for (DWORD i = 0; i < dwLen1; ++i)
        {
            if (s1[i] != s2[i])
                return s1[i] - s2[i];
        }
        return 0;
    }

    int stricmpA(LPCSTR s1, LPCSTR s2)
    {
        return System::SysCall("_stricmp", ccCdecl, 8, s1, s2);
    }

    LPCWSTR ExtractFileName(LPCWSTR lpFilePath)
    {
        PCWCHAR pLetter = lpFilePath + strlenW(lpFilePath);
        while ((*pLetter != '\\') && (*pLetter != '/') && ((DWORD)pLetter > (DWORD)lpFilePath))
            --pLetter;
        return ++pLetter;
    }

    LPWSTR ExtractFileDirectory(LPCWSTR lpFilePath, LPWSTR lpDirectory)
    {
        PCWCHAR pLetter = lpFilePath + strlenW(lpFilePath);
        while ((*pLetter != '\\') && (*pLetter != '/') && ((DWORD)pLetter > (DWORD)lpFilePath))
            pLetter--;
        DWORD dwSize = (DWORD)++pLetter - (DWORD)lpFilePath;
        memcpy(lpDirectory, lpFilePath, dwSize);
        *(PWCHAR)((DWORD)lpDirectory + dwSize) = 0;
        return lpDirectory;
    }

} // namespace Helpers
