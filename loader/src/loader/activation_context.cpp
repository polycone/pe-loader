#include "loader.h"
#include "../errors.h"
#include "../helpers.h"
#include "../system/syscalls.h"

/*
  Description:
    Finds first RT_MANIFEST resource
  Arguments:
    pImage - pointer to a valid image descriptor
    lpName - pointer to the variable that receives the name pointer
  Return Value:
    BOOL - true if resource was found
*/
BOOL LdrFindManifestResource(PIMAGE_DESCRIPTOR pImage, LPWSTR *lpName)
{
    if (IS_NULL(pImage) || IS_NULL(lpName))
        return false;

    if (LdrCheckDataDirectory(pImage, IMAGE_DIRECTORY_ENTRY_RESOURCE) != E_SUCCESS)
        return false;

    // Fall into root "type" directory

    LPVOID lpBase = MAKE_PTR(PIMAGE_RESOURCE_DIRECTORY, pImage->pImageBase,
                             pImage->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);

    PIMAGE_RESOURCE_DIRECTORY pResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)lpBase;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = MAKE_PTR(PIMAGE_RESOURCE_DIRECTORY_ENTRY, lpBase,
                                                              sizeof(IMAGE_RESOURCE_DIRECTORY));
    pResourceEntry += pResourceDirectory->NumberOfNamedEntries;
    for (int i = 0; i < pResourceDirectory->NumberOfIdEntries; ++i, ++pResourceEntry)
    {

        // if resource entry is RT_MANIFEST

        if (pResourceEntry->Id == (WORD)RT_MANIFEST)
        {
            if (pResourceEntry->DataIsDirectory)
            {

                // Fall into "name" directory

                pResourceDirectory = MAKE_PTR(PIMAGE_RESOURCE_DIRECTORY, lpBase,
                                              pResourceEntry->OffsetToDirectory);
                pResourceEntry = MAKE_PTR(PIMAGE_RESOURCE_DIRECTORY_ENTRY, pResourceDirectory,
                                                              sizeof(IMAGE_RESOURCE_DIRECTORY));

                // Get the first resource name

                if (pResourceDirectory->NumberOfNamedEntries + pResourceDirectory->NumberOfIdEntries)
                {
                    if (pResourceEntry->NameIsString)
                    {
                        PIMAGE_RESOURCE_DIRECTORY_STRING pString = MAKE_PTR(PIMAGE_RESOURCE_DIRECTORY_STRING, lpBase,
                                                                            pResourceEntry->NameOffset);
                        *lpName = (LPWSTR)System::MmAlloc((pString->Length + 1) * sizeof(WCHAR), true);
                        memcpy(*lpName, pString->NameString, (pString->Length + 1) * sizeof(WCHAR));
                    }
                    else
                    {
                        *lpName = (LPWSTR)pResourceEntry->Id;
                    }
                }
                break;
            }
        }
    }
    return true;
}

/*
  Description:
    Sets process default activation context
  Arguments:
    pImage - pointer to a valid image descriptor
    pActivationContext - pointer to an image activation context what receive created context
  Return Value:
    int - error code
*/
int LdrSetDefaultActivationContext(PIMAGE_DESCRIPTOR pImage, PIMAGE_ACTIVATION_CONTEXT pActivationContext)
{
    if (IS_NULL(pImage) || IS_NULL(pActivationContext))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    LPWSTR lpDirectory = NULL;
    __try
    {        
        PPEB pPeb = NtCurrentTeb()->Peb;
        pActivationContext->hActivationContext = INVALID_HANDLE_VALUE;
        pActivationContext->hFileActivationContext = INVALID_HANDLE_VALUE;
        pActivationContext->ulFileCookie = 0;
        pActivationContext->hOldActivationContext = pPeb->lpActivationContextData;

        ACTCTXW actCtx;
        memset(&actCtx, 0, sizeof(ACTCTXW));
        actCtx.cbSize  = sizeof(actCtx);

        // Firstly try to find first RT_MANIFEST resource

        DWORD dwLength = Helpers::strlenW(System::GetExecutableFileName()->Buffer);
        lpDirectory = (LPWSTR)System::MmAlloc((dwLength + 1) * sizeof(WCHAR), true);
        lpDirectory = Helpers::ExtractFileDirectory(System::GetExecutableFileName()->Buffer, lpDirectory);

        LPWSTR lpName = NULL;
        bool bLoaded = false;
        LdrFindManifestResource(pImage, &lpName);

        // If resource found try to create activation context from it

        if (!IS_NULL(lpName))
        {
            actCtx.dwFlags = ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID;
            actCtx.hModule = (HMODULE)pImage->pImageBase;
            actCtx.lpResourceName = lpName;
            actCtx.lpAssemblyDirectory = lpDirectory;
            pActivationContext->hActivationContext = CreateActCtxW(&actCtx);
            if (pActivationContext->hActivationContext != INVALID_HANDLE_VALUE)
            {
                bLoaded = true;
            }
#ifdef _LDR_DEBUG_
            else
            {
                System::SysDbgMessage(L"[W] CreateActCtx return invalid handle value, error: 0x%08X\n", GetLastError());
            }
#endif
            if (!IS_INTRESOURCE(lpName))
                System::MmFree(lpName);
        }
#ifdef _LDR_DEBUG_
        else
        {
            LPCWSTR lpFileName = Helpers::ExtractFileName(System::GetExecutableFileName()->Buffer);
            System::SysDbgMessage(L"[W] Image contain no manifest resources, check for %s.manifest\n", lpFileName);
        }
#endif

        // try to load data from "filename.extension.manifest"

        memset(&actCtx, 0, sizeof(ACTCTXW));
        actCtx.cbSize  = sizeof(actCtx);
        actCtx.lpAssemblyDirectory = lpDirectory;
        actCtx.dwFlags = ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID;

        LPWSTR lpManifest = (LPWSTR)System::MmAlloc((dwLength + 10) * sizeof(WCHAR), true);
        memcpy(lpManifest, System::GetExecutableFileName()->Buffer, dwLength * sizeof(WCHAR));
        memcpy(lpManifest + dwLength, L".manifest", 9 * sizeof(WCHAR));

        actCtx.lpSource = lpManifest;
        pActivationContext->hFileActivationContext = CreateActCtxW(&actCtx);
        System::MmFree(lpManifest);
        if ((pActivationContext->hFileActivationContext != INVALID_HANDLE_VALUE) || 
            (pActivationContext->hActivationContext != INVALID_HANDLE_VALUE))
        {
            bLoaded = true;
        }
#ifdef _LDR_DEBUG_
        else
        {
            System::SysDbgMessage(L"[W] CreateActCtx return invalid handle value, error: 0x%08X\n", GetLastError());
        }
#endif

        if (!bLoaded)
        {
            // If both, resource nor manifest file not exists or have invalid data

#ifdef _LDR_DEBUG_
            System::SysDbgMessage(L"[W] Application has no manifest\n");
#endif
            System::MmFree(lpDirectory);
            return System::SetErrorCode(E_NO_MANIFEST);
        }

        // Set process default activation context data
        pActivationContext->ulFileCookie = 0;
        if ((pActivationContext->hFileActivationContext != INVALID_HANDLE_VALUE) &&
            (pActivationContext->hActivationContext != INVALID_HANDLE_VALUE))
            ActivateActCtx(pActivationContext->hFileActivationContext, &pActivationContext->ulFileCookie);

        DWORD actCtxOffset = 0;

        switch (System::GetOSVersion())
        {
        case VER_WINDOWS_XP:
        case VER_WINDOWS_SERVER_2003:
            actCtxOffset = ACTIVATION_CONTEXT_DATA_OFFSET_XP;
            break;
        case VER_WINDOWS_VISTA:
        case VER_WINDOWS_7:
        case VER_WINDOWS_8:
            actCtxOffset = ACTIVATION_CONTEXT_DATA_OFFSET_WIN8;
            break;
        }
        if (pActivationContext->hActivationContext != INVALID_HANDLE_VALUE)
            pPeb->lpActivationContextData = (LPVOID)*MAKE_PTR(PDWORD, pActivationContext->hActivationContext, actCtxOffset);
        else if (pActivationContext->hFileActivationContext != INVALID_HANDLE_VALUE)
            pPeb->lpActivationContextData = (LPVOID)*MAKE_PTR(PDWORD, pActivationContext->hFileActivationContext, actCtxOffset);
    } // __try
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif
        System::MmFree(lpDirectory);
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
    System::MmFree(lpDirectory);
    return System::SetErrorCode(E_SUCCESS);
}

/*
  Description:
    Restore process default activation context
  Arguments:
    pActivationContext - pointer to an image activation context
  Return Value:
    int - error code
*/
int LdrRestoreDefaultActivationContext(PIMAGE_ACTIVATION_CONTEXT pActivationContext)
{
    if (IS_NULL(pActivationContext))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    __try
    {        
        PPEB pPeb = NtCurrentTeb()->Peb;

        if (pActivationContext->ulFileCookie != 0)
            DeactivateActCtx(0, pActivationContext->ulFileCookie);

        pPeb->lpActivationContextData = pActivationContext->hOldActivationContext;
        if (pActivationContext->hActivationContext != INVALID_HANDLE_VALUE)
            ReleaseActCtx(pActivationContext->hActivationContext);
        if (pActivationContext->hFileActivationContext != INVALID_HANDLE_VALUE)
            ReleaseActCtx(pActivationContext->hFileActivationContext);
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
