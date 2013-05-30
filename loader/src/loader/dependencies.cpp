/*
 * Image import & export table helpers
 */

#include <Windows.h>
#include <Psapi.h>
#include "loader.h"
#include "../errors.h"
#include "../helpers.h"

/*
  Description:
    Set section (which contains selected data directory) protection flags to "rwe"
  Arguments:
    pImage - pointer to a valid image descriptor
    dwDataDirectory - data directory code
*/
void LdrAllowImageDirectoryAccess(PIMAGE_DESCRIPTOR pImage, DWORD dwDataDirectory)
{
    __try
    {
        if (LdrCheckDataDirectory(pImage, dwDataDirectory) != E_SUCCESS)
            return;
        DWORD dwDirectory = pImage->pOptionalHeader->DataDirectory[dwDataDirectory].VirtualAddress;
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)pImage->pSections;
        DWORD dwProtect = 0;

        // Scan image sections to find section which contains data directory

        for (int section = 0; section < pImage->pFileHeader->NumberOfSections; ++section, ++pSection)
        {
            if (IS_IN_RANGE_SZ(dwDirectory, pSection->VirtualAddress, pSection->Misc.VirtualSize))
            {
                VirtualProtect(MAKE_LPVOID(pImage->pImageBase, pSection->VirtualAddress), 
                               pSection->Misc.VirtualSize, PAGE_EXECUTE_WRITECOPY, &dwProtect);
                break;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif //_LDR_DEBUG_
    }
}

/*
  LdrSetExportAddress helper routine (For details see: LdrSetExportAddress)
*/
int LdrSetExportAddressHelper(PIMAGE_DESCRIPTOR pImage, LPCSTR lpName, LPVOID lpAddress)
{
    if (IS_NULL(pImage) || IS_NULL(lpName))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    __try
    {
        if (LdrCheckDataDirectory(pImage, IMAGE_DIRECTORY_ENTRY_EXPORT) != E_SUCCESS)
            return System::SetErrorCode(E_NO_EXPORT);
        PIMAGE_EXPORT_DIRECTORY pExport = MAKE_PTR(PIMAGE_EXPORT_DIRECTORY, pImage->pImageBase, 
                                          pImage->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if (IS_NULL(pExport))
            return System::SetErrorCode(E_NO_EXPORT);
        if (pExport->NumberOfNames == 0)
            return System::SetErrorCode(E_NO_EXPORT_NAMES);

        // Scan image export directory for matching name (lpName)

        PDWORD pName = (PDWORD)pExport->AddressOfNames;
        PWORD pOrdinals = MAKE_PTR(PWORD, pImage->pImageBase, pExport->AddressOfNameOrdinals);
        for (unsigned int i = 0; i < pExport->NumberOfNames; ++i, ++pName)
        {
            DWORD dwNameAddr = (DWORD)pImage->pImageBase + (DWORD)pName;
            dwNameAddr = (DWORD)pImage->pImageBase + *(DWORD*)dwNameAddr;
            LPSTR lpExportName = (LPSTR)(dwNameAddr);
            if (Helpers::strcmpA(lpName, lpExportName) == 0)
            {
                PDWORD dwExportAddress = MAKE_PTR(PDWORD, pImage->pImageBase,
                                         pExport->AddressOfFunctions + sizeof(PDWORD) * (pOrdinals[i]));
                __try
                {
                    *dwExportAddress = (DWORD)lpAddress - (DWORD)pImage->pImageBase;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
#ifdef _LDR_DEBUG_
                    System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif //_LDR_DEBUG_
                    return System::SetErrorCode(E_NO_ACCESS);
                }
                return System::SetErrorCode(E_SUCCESS);
            }
        }
        return System::SetErrorCode(E_NO_EXPORT_PROC);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif //_LDR_DEBUG_
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
}

/*
  Description:
    Replace selected function pointer in the image export table to the defined value
  Arguments:
    pImage - pointer to a valid image descriptor
    lpName - export function name
    lpNewAddress - new address of exported function
  Return Value:
    int - error code
*/
int LdrSetExportAddress(PIMAGE_DESCRIPTOR pImage, LPCSTR lpName, LPVOID lpNewAddress)
{
    int errorCode = LdrSetExportAddressHelper(pImage, lpName, lpNewAddress);
    if (errorCode == E_NO_ACCESS)
    {
        // Try to get access to exported function table if program naven't it yet

        LdrAllowImageDirectoryAccess(pImage, IMAGE_DIRECTORY_ENTRY_EXPORT);
        errorCode = LdrSetExportAddressHelper(pImage, lpName, lpNewAddress);
    }
    return errorCode;
}

/*
  Description:
    Binds image import thunk
  Arguments:
    pImageBase - pointer to a valid image base address
    hBindLibrary - handle of the binding library
    pLookup - address of image lookup table entry
    pThunk - address of image thunk table entry
  Return Value:
    int - error code
*/
int LdrBindImportThunk(LPVOID pImageBase, HMODULE hBindLibrary, PIMAGE_THUNK_DATA pLookup, PIMAGE_THUNK_DATA pThunk)
{
    DWORD dwOriginalThunk = pLookup->u1.Function;
    if(pLookup->u1.Ordinal & IMAGE_ORDINAL_FLAG) 
        pThunk->u1.Function = (DWORD)GetProcAddress(hBindLibrary, (char*)(IMAGE_ORDINAL(pLookup->u1.Ordinal)));
    else
        pThunk->u1.Function = (DWORD)GetProcAddress(hBindLibrary, (LPCSTR)(MAKE_PTR(PIMAGE_IMPORT_BY_NAME, 
                                                    pImageBase, pLookup->u1.AddressOfData))->Name);
    if (IS_NULL(pThunk->u1.Function))
    {

        WCHAR lpLibraryName[MAX_PATH];
        GetModuleBaseNameW((HANDLE)-1, hBindLibrary, lpLibraryName, MAX_PATH);
#ifdef _LDR_DEBUG_
        if(dwOriginalThunk & IMAGE_ORDINAL_FLAG)
            System::SysDbgMessage(L"[E] Failed to obtain address of index %d from %s\n", 
                                  IMAGE_ORDINAL(pLookup->u1.Ordinal), lpLibraryName);
        else
            System::SysDbgMessage(L"[E] Failed to obtain address of index %d from %s\n", 
                                  (MAKE_PTR(PIMAGE_IMPORT_BY_NAME, pImageBase, dwOriginalThunk))->Name, 
                                  lpLibraryName);
#endif //_LDR_DEBUG_

        if(dwOriginalThunk & IMAGE_ORDINAL_FLAG)
            return System::SetErrorCode(E_FUNCTION_NOT_FOUND_ORD, true, IMAGE_ORDINAL(pLookup->u1.Ordinal),
                                        lpLibraryName);
        else
            return System::SetErrorCode(E_FUNCTION_NOT_FOUND, true, (MAKE_PTR(PIMAGE_IMPORT_BY_NAME, 
                                        pImageBase, dwOriginalThunk))->Name, lpLibraryName);
    }
    return System::SetErrorCode(E_SUCCESS);
}

/*
  Description:
    Binds image import table
  Arguments:
    pImage - pointer to a valid image descriptor
    hBindLibrary - handle of the binding library
    pImport - pointer to valid entry in image import table
    bBindForwadingOnly - if true, bind only forwarded functions
  Return Value:
    int - error code
*/
int LdrBindImport(PIMAGE_DESCRIPTOR pImage, HMODULE hBindLibrary, PIMAGE_IMPORT_DESCRIPTOR pImport, bool bBindForwadingOnly)
{
    PIMAGE_THUNK_DATA pThunk, pLookup;

    if (bBindForwadingOnly)
    {
        // Bind only forwarder chain functions

        ULONG ulForwarderChain = pImport->ForwarderChain;
        while (ulForwarderChain != -1)
        {
            pLookup = MAKE_PTR(PIMAGE_THUNK_DATA, pImage->pImageBase, 
                      pImport->OriginalFirstThunk + (ulForwarderChain * sizeof(IMAGE_THUNK_DATA)));
            pThunk = MAKE_PTR(PIMAGE_THUNK_DATA, pImage->pImageBase, 
                     pImport->FirstThunk + (ulForwarderChain * sizeof(IMAGE_THUNK_DATA)));
            ulForwarderChain = (ULONG)pThunk->u1.Ordinal;

            if (LdrBindImportThunk(pImage->pImageBase, hBindLibrary, pLookup, pThunk) != E_SUCCESS)
                return System::GetErrorCode(false);
        }

    }
    else if (pImport->FirstThunk)
    {
        pThunk = MAKE_PTR(PIMAGE_THUNK_DATA, pImage->pImageBase, pImport->FirstThunk);

        if (pImport->OriginalFirstThunk < pImage->pOptionalHeader->SizeOfHeaders ||
            pImport->OriginalFirstThunk >= pImage->pOptionalHeader->SizeOfImage)
        {
            pLookup = pThunk;
        }
        else
        {
            pLookup = (PIMAGE_THUNK_DATA)((pImport->OriginalFirstThunk == 0) ? pThunk : MAKE_LPVOID(pImage->pImageBase, 
                                                                                        pImport->OriginalFirstThunk));
        }
            
        // Bind each image import thunk

        while (pLookup->u1.Ordinal != 0)
        {
            if (LdrBindImportThunk(pImage->pImageBase, hBindLibrary, pLookup, pThunk) != E_SUCCESS)
                return System::GetErrorCode(false);
            ++pLookup;
            ++pThunk;
        }
    }
    return System::SetErrorCode(E_SUCCESS);
}

/*
  Description:
    Fills the image import address table with apropriate values
  Arguments:
    pImage - pointer to a valid image descriptor
    bBreakOnFail - immediate return with appropriate error code if
                   some imported function cannot be resolved
  Return Value:
    int - error code
*/
int LdrProcessImports(PIMAGE_DESCRIPTOR pImage)
{
    HMODULE hLib;
    if (IS_NULL(pImage))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    __try
    {
        PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImport = NULL;
        if (LdrCheckDataDirectory(pImage, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) == E_SUCCESS)
            pBoundImport = MAKE_PTR(PIMAGE_BOUND_IMPORT_DESCRIPTOR, pImage->pImageBase, 
                           pImage->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
        PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;
        if (LdrCheckDataDirectory(pImage, IMAGE_DIRECTORY_ENTRY_IMPORT) == E_SUCCESS)
            pImport = MAKE_PTR(PIMAGE_IMPORT_DESCRIPTOR, pImage->pImageBase, 
                      pImage->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        if (!IS_NULL(pBoundImport))
        {
            LPSTR lpLbraryNameBase = (LPSTR)pBoundImport;
            bool bDirtyBinding = false;

            // Walk bound import libraries

            while (pBoundImport->OffsetModuleName)
            {
                LPSTR lpLibraryName = lpLbraryNameBase + pBoundImport->OffsetModuleName;
#ifdef _LDR_DEBUG_
                System::SysDbgMessage(L"[I] Loading: %S\n", lpLibraryName);
#endif //_LDR_DEBUG_
                hLib = LoadLibraryA(lpLibraryName);
                if (IS_NULL(hLib))
                {
#ifdef _LDR_DEBUG_
                    System::SysDbgMessage(L"[E] Failed to load %S\n", lpLibraryName);
#endif //_LDR_DEBUG_
                    return System::SetErrorCode(E_LIBRARY_FAIL, true, lpLibraryName);
                }

                PLDR_DATA_TABLE_ENTRY pLdrEntry = System::GetSystemLdrTableEntry(hLib);
                if (pBoundImport->TimeDateStamp != pLdrEntry->TimeDateStamp ||
                    (pLdrEntry->Flags && LDRP_IMAGE_NOT_AT_BASE))
                    bDirtyBinding = true;

                PIMAGE_BOUND_FORWARDER_REF pBoundForwarder = (PIMAGE_BOUND_FORWARDER_REF)(pBoundImport + 1);

                // Walk module forwarder references

                for (int i = 0; i < pBoundImport->NumberOfModuleForwarderRefs; ++i) 
                {
                    LPSTR lpModuleName = lpLbraryNameBase + pBoundForwarder->OffsetModuleName;
#ifdef _LDR_DEBUG_
                    System::SysDbgMessage(L"[I] Loading: %S\n", lpModuleName);
#endif //_LDR_DEBUG_
                    HMODULE hLib = LoadLibraryA(lpModuleName);
                    
                    if (IS_NULL(hLib))
                    {
#ifdef _LDR_DEBUG_
                        System::SysDbgMessage(L"[E] Failed to load %S\n", lpModuleName);
#endif //_LDR_DEBUG_
                        return System::SetErrorCode(E_LIBRARY_FAIL, true, lpModuleName);
                    }
                    PLDR_DATA_TABLE_ENTRY pLdrEntry = System::GetSystemLdrTableEntry(hLib);
                    if (pBoundImport->TimeDateStamp != pLdrEntry->TimeDateStamp ||
                        (pLdrEntry->Flags && LDRP_IMAGE_NOT_AT_BASE))
                        bDirtyBinding = true;
                                           
                    ++pBoundForwarder;
                }

                pBoundImport = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)pBoundForwarder;

                if (bDirtyBinding)
                {

                    // If binding is invalid use the default IAT

                    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = pImport;
                    if (IS_NULL(pImportDesc))
                        return System::SetErrorCode(E_NO_IMPORT, true, lpLibraryName);

                    while (pImport->Name) 
                    {
                        LPSTR lpImportName = MAKE_PTR(LPSTR, pImage->pImageBase, pImport->Name);
                        if (!Helpers::stricmpA(lpImportName, lpLibraryName))
                            break;
                        ++pImport;
                    }
                    if (IS_NULL(pImport->Name))
                        return System::SetErrorCode(E_INVALID_IMPORT_NAME);
                    if (LdrBindImport(pImage, hLib, pImport, false) != E_SUCCESS)
                        return System::GetErrorCode(false);
                }
            }

        }
        else if (!IS_NULL(pImport))
        {
            LPCSTR lpLibraryName;
            bool bBindForwardingOnly = false;
            PLDR_DATA_TABLE_ENTRY pLdrEntry;

            // Load each library from image import table
            
            while (pImport->Name != 0 && pImport->FirstThunk)
            {
                bBindForwardingOnly = false;

                if (IS_NULL((MAKE_PTR(PIMAGE_THUNK_DATA, pImage->pImageBase, pImport->FirstThunk))->u1.Function))
                    goto _bypass_library;

                lpLibraryName = MAKE_PTR(LPCSTR, pImage->pImageBase, pImport->Name);
#ifdef _LDR_DEBUG_
                System::SysDbgMessage(L"[I] Loading: %S\n", lpLibraryName);
#endif //_LDR_DEBUG_

                hLib = LoadLibraryA(lpLibraryName);
                if (IS_NULL(hLib))
                {
#ifdef _LDR_DEBUG_
                    System::SysDbgMessage(L"[E] Failed to load %S\n", lpLibraryName);
#endif //_LDR_DEBUG_
                    return System::SetErrorCode(E_LIBRARY_FAIL, true, lpLibraryName);
                }

                // Check if image has been bound

                if (pImport->OriginalFirstThunk) 
                {
                    pLdrEntry = System::GetSystemLdrTableEntry(hLib);
                    if (pImport->TimeDateStamp && pImport->TimeDateStamp == pLdrEntry->TimeDateStamp &&
                        (!pLdrEntry->Flags && LDRP_IMAGE_NOT_AT_BASE))
                    {
                        if (pImport->ForwarderChain == -1)
                            goto _bypass_library;
                        bBindForwardingOnly = true;
                    }
                }

                if (LdrBindImport(pImage, hLib, pImport, bBindForwardingOnly) != E_SUCCESS)
                    return System::GetErrorCode(false);
_bypass_library:
                ++pImport;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d] (le:%d)\n", __FUNCTIONW__, __FILEW__, __LINE__, GetLastError());
#endif //_LDR_DEBUG_
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
    return System::SetErrorCode(E_SUCCESS);
}

/*
  LdrSetImportAddress helper routine (For details see: LdrSetImportAddress)
*/
int LdrSetImportAddressHelper(PIMAGE_DESCRIPTOR pImage, LPCSTR lpLibName, LPCSTR lpFuncName, LPVOID lpAddress)
{
    __try
    {
        PIMAGE_IMPORT_DESCRIPTOR pImport = MAKE_PTR(PIMAGE_IMPORT_DESCRIPTOR, pImage->pImageBase, 
                                           pImage->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        PIMAGE_THUNK_DATA pThunk, pLookup;
        LPCSTR pLibraryName;

        // Scan for selected library

        while (pImport->Name != 0)
        {
            pLibraryName = MAKE_PTR(LPCSTR, pImage->pImageBase, pImport->Name);
            if (Helpers::stricmpA(pLibraryName, lpLibName) == 0)
            {
                pThunk = MAKE_PTR(PIMAGE_THUNK_DATA, pImage->pImageBase, pImport->FirstThunk);
                pLookup = (PIMAGE_THUNK_DATA)((pImport->OriginalFirstThunk == 0) ? pThunk : MAKE_LPVOID(pImage->pImageBase, 
                                                                                            pImport->OriginalFirstThunk));

                // Check for original thunk

                if (pThunk->u1.Function == pLookup->u1.Function)
                    return System::SetErrorCode(E_NO_ORIGINAL_THUNK);

                // Scan imported functions names

                LPCSTR lpName = NULL;
                while (pLookup->u1.Ordinal != 0)
                {
                    if(!(pLookup->u1.Ordinal & IMAGE_ORDINAL_FLAG)) 
                    {
                        lpName = (LPCSTR)(MAKE_PTR(PIMAGE_IMPORT_BY_NAME, 
                                          pImage->pImageBase, pLookup->u1.AddressOfData))->Name;
                    
                        if (Helpers::strcmpA(lpName, lpFuncName) == 0)
                        {
                            __try
                            {
                                pThunk->u1.Function = (DWORD)lpAddress;
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {
#ifdef _LDR_DEBUG_
                                System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif //_LDR_DEBUG_
                                return System::SetErrorCode(E_NO_ACCESS);
                            }
                            return System::SetErrorCode(E_SUCCESS);
                        }
                    }
                    ++pLookup;
                    ++pThunk;
                }
            }
            ++pImport;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif //_LDR_DEBUG_
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
    return System::SetErrorCode(E_IMPORT_NOT_FOUND);
}

/*
  Description:
    Set image import address of selected library and function name (only if original thunk is persist)
  Arguments:
    pImage - pointer to a valid image descriptor
    lpLibName - library name from which function was imported
    lpFuncName - import function name
    lpAddress - new function address
  Return Value:
    int - error code
*/
int LdrSetImportAddress(PIMAGE_DESCRIPTOR pImage, LPCSTR lpLibName, LPCSTR lpFuncName, LPVOID lpAddress)
{
    if (IS_NULL(pImage) || IS_NULL(lpLibName) || IS_NULL(lpFuncName))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    int errorCode = LdrSetImportAddressHelper(pImage, lpLibName, lpFuncName, lpAddress);
    if (errorCode == E_NO_ACCESS)
    {
        // Try to get access to import function table if program naven't it yet

        LdrAllowImageDirectoryAccess(pImage, IMAGE_DIRECTORY_ENTRY_IMPORT);
        LdrAllowImageDirectoryAccess(pImage, IMAGE_DIRECTORY_ENTRY_IAT);
        errorCode = LdrSetImportAddressHelper(pImage, lpLibName, lpFuncName, lpAddress);
    }
    return errorCode;
}
