/*
 * Image relocation helper
 */

#include "loader.h"
#include "../errors.h"

/*
  Description:
    Process image relocations
  Arguments:
    pImage - pointer to valid image descriptor
    dwCustomDelta - delta value (offset from image default base address) 
                    if value is -1 function calculate delta
  Return Value:
    int - error code
*/
int LdrProcessRelocations(PIMAGE_DESCRIPTOR pImage, DWORD dwCustomDelta)
{    
    __try
    {
        if (IS_NULL(pImage))
            return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);

        // Check for image relocation availability
        // and calculate delta value if needed

        DWORD dwDelta = 0;
        if (dwCustomDelta != -1)
            dwDelta = dwCustomDelta;
        else
            dwDelta = (DWORD)pImage->pImageBase - pImage->pOptionalHeader->ImageBase;
        if (dwDelta == 0)
            return System::SetErrorCode(E_RELOCATION_NOT_NEEDED);
        PIMAGE_DATA_DIRECTORY pRelocDirectory = &pImage->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (pRelocDirectory->VirtualAddress == 0)
            return System::SetErrorCode(E_RELOCATION_NOT_FOUND, true);
        DWORD dwLimit = (DWORD)pImage->pImageBase + pRelocDirectory->VirtualAddress + pRelocDirectory->Size;
        PIMAGE_BASE_RELOCATION pRelocation = MAKE_PTR(PIMAGE_BASE_RELOCATION, pImage->pImageBase, 
                                             pRelocDirectory->VirtualAddress);
        PIMAGE_RELOC pReloc;

        // Process image relocations

        while ((DWORD)pRelocation < dwLimit)
        {
            DWORD dwRelocLimit = (DWORD)pRelocation + pRelocation->SizeOfBlock;
            DWORD lpBase = (DWORD)pImage->pImageBase + pRelocation->VirtualAddress;
            pReloc = (PIMAGE_RELOC)((DWORD)pRelocation + sizeof(IMAGE_BASE_RELOCATION));
            while ((DWORD)pReloc < dwRelocLimit)
            {
                switch (pReloc->wType)
                {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        break;
                    case IMAGE_REL_BASED_HIGH:
                        *((WORD*)(lpBase + pReloc->wOffset)) += HIWORD(dwDelta);
                        break;
                    case IMAGE_REL_BASED_LOW:
                        *((WORD*)(lpBase + pReloc->wOffset)) += LOWORD(dwDelta);
                        break;
                    case IMAGE_REL_BASED_HIGHLOW:
                        *((DWORD*)(lpBase + pReloc->wOffset)) += dwDelta;
                        break;
                    case IMAGE_REL_BASED_DIR64:
                        *((ULONGLONG*)(lpBase + pReloc->wOffset)) += dwDelta;
                        break;
                    case IMAGE_REL_BASED_HIGHADJ:
                    {
                        *((WORD*)(lpBase + pReloc->wOffset)) += HIWORD(dwDelta);
                        *((WORD*)(lpBase + pReloc->wOffset + 2)) = (++pReloc)->wData;
                        break;
                    }
                    default:
                        return System::SetErrorCode(E_UNKNOWN_RELOC, true, pReloc->wType);
                }
                ++pReloc;
            }
            pRelocation = (PIMAGE_BASE_RELOCATION)pReloc;
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
