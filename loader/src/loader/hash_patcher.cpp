/*
 * Windows loader data table hash patcher
 */

#include "loader.h"
#include "../errors.h"
#include "../system/syscalls.h"

namespace WindowsXP
{

    /*
      Description:
        Windows XP native loader hash function
      Arguments:
        pString - pointer to a valid uncode string
        pHashValue - pointer to hash value receiver
      Return Value:
        int - error code
    */
    int HashUnicodeString(PUNICODE_STRING pString, PULONG pHashValue)
    {
        if (IS_NULL(pString) || IS_NULL(pHashValue))
            return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
        *pHashValue = 0;
        if (pString->Length != 0)
            *pHashValue = System::SysCall("RtlUpcaseUnicodeChar", ccStdcall, 4, pString->Buffer[0]) - 1;
        return System::SetErrorCode(E_SUCCESS);
    }

} // namespace WindowsXP

namespace Windows7
{

    /*
      Description:
        Windows 7 native loader hash function
      Arguments:
        pString - pointer to a valid uncode string
        pHashValue - pointer to hash value receiver
      Return Value:
        int - error code
    */
    int HashUnicodeString(PUNICODE_STRING pString, PULONG pHashValue)
    {
        if (IS_NULL(pString) || IS_NULL(pHashValue))
            return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
        HMODULE hSystemDll = GetModuleHandleW(L"ntdll.dll");
        WCHAR (__stdcall *RtlUpcaseUnicodeChar)(WCHAR wChar) = NULL;
        RtlUpcaseUnicodeChar = (WCHAR (__stdcall *)(WCHAR))GetProcAddress(hSystemDll, "RtlUpcaseUnicodeChar");
        if (IS_NULL(RtlUpcaseUnicodeChar))
            return System::SetErrorCode(E_HASH_ERROR);
        *pHashValue = 0;
        if (pString->Length != 0)
        {
            LPCWCHAR lpChar = MAKE_PTR(LPCWCHAR, pString->Buffer, pString->Length - sizeof(WCHAR));
            WCHAR wUpcase = 0;
            while (lpChar >= pString->Buffer)
            {
                wUpcase = RtlUpcaseUnicodeChar(*lpChar);
                *pHashValue += (ULONG)wUpcase * 0x1003F;
                --lpChar;
            }
        }
        return System::SetErrorCode(E_SUCCESS);
    }

} // namespace Windows7

/*
  Description:
    Windows 7/8 native loader hash functions assembly
  Arguments:
    lpString - pointer to a valid uncode string
    pHashValue - pointer to hash value receiver
  Return Value:
    int - error code
*/
int LdrHashUnicodeString(LPCWSTR lpString, PULONG pHashValue)
{
    if (IS_NULL(pHashValue))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    UNICODE_STRING usData;
    RtlInitUnicodeString(&usData, lpString);    
    switch (System::GetOSVersion())
    {
    case VER_WINDOWS_8:
        if (RtlHashUnicodeString(&usData, true, 0, pHashValue) != 0)
            return System::SetErrorCode(E_HASH_ERROR);
        return System::SetErrorCode(E_SUCCESS);
    case VER_WINDOWS_7:
        return Windows7::HashUnicodeString(&usData, pHashValue);
    case VER_WINDOWS_XP:
    case VER_WINDOWS_SERVER_2003:
    case VER_WINDOWS_VISTA:
        return WindowsXP::HashUnicodeString(&usData, pHashValue);
    default:
        return System::SetErrorCode(E_UNSUPPORTED_SYSTEM);
    }
    return System::SetErrorCode(E_ERROR);
}

/*
  Description:
    Patches windows system loader hash table
  Arguments:
    pLdrEntry - pointer to a valid system loader data table entry
    lpOriginalName - original module name
    lpNewName - new module name
  Return Value:
    int - error code
*/
int LdrPatchHashTable(PLDR_DATA_TABLE_ENTRY pLdrEntry, LPCWSTR lpOriginalName, LPCWSTR lpNewName)
{        
    if (IS_NULL(pLdrEntry) || IS_NULL(lpOriginalName) || IS_NULL(lpNewName))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    __try
    {
        ULONG uHashValue = 0;
        if (LdrHashUnicodeString(lpOriginalName, &uHashValue) != E_SUCCESS)
            return System::GetErrorCode(false);

        // Try to find loader hash table first element
        // 1. calculate hash table index
        // 2. find hash table entry (head for hash links)
        // 3. get pointer to hash table

        DWORD dwTableIndex = uHashValue & LDR_HASH_TABLE_MASK;
        DWORD dwNtdllBase = (DWORD)GetModuleHandleW(L"ntdll.dll");
        PLIST_ENTRY pHashLink = &pLdrEntry->HashLinks;

        // Find list head (list head is a static const value in the ntdll).

        PLIST_ENTRY pCurrentItem = pHashLink;
        PLIST_ENTRY pListCycle = pCurrentItem;
        do
        {
            pCurrentItem = pCurrentItem->Blink;
        }
        while (((DWORD)pCurrentItem < dwNtdllBase) && (pCurrentItem != pListCycle));

        if (pCurrentItem == pListCycle)
            return System::SetErrorCode(E_HASH_HEAD_NOT_FOUND);

        PLIST_ENTRY pHashTable = (PLIST_ENTRY)((DWORD)pCurrentItem - dwTableIndex * sizeof(LIST_ENTRY));
        ULONG uNewHash = 0;
        if (LdrHashUnicodeString(lpNewName, &uNewHash) != E_SUCCESS)
            return System::GetErrorCode(false);

        //Allow to write to ntdll memory

        DWORD dwOldProtect;
        if (!VirtualProtect(pHashTable, LDR_HASH_TABLE_SIZE * sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOldProtect))
            return System::SetErrorCode(E_ACCESS_DENIED);

        //Remove data from old hash list

        pHashLink->Blink->Flink = pHashLink->Flink;
        pHashLink->Flink->Blink = pHashLink->Blink;

        //Insert data into new hash entry

        DWORD dwNewIndex = uNewHash & LDR_HASH_TABLE_MASK;

        PLIST_ENTRY pNewHashList = pHashTable + dwNewIndex;
        LIST_ENTRY pHashListOrig = *pNewHashList;

        pHashListOrig.Blink->Flink = pHashLink;
        pHashLink->Blink = pHashListOrig.Blink;
        pNewHashList->Blink = pHashLink;
        pHashLink->Flink = pNewHashList;

        // Do the platform-dependent operations

        if (System::GetOSVersion() >= VER_WINDOWS_8)
        {
            ((Windows8::PLDR_DATA_TABLE_ENTRY)pLdrEntry)->BaseNameHashValue = uNewHash;
        }

    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
    return System::SetErrorCode(E_SUCCESS);
}
