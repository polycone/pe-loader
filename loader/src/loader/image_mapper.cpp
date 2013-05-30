/*
 * Image mapper functions
 */

#include "loader.h"
#include "../errors.h"
#include "../system/syscalls.h"

/*
  Description:
    Helper function for reserving process address space.
  Arguments:
    pNtHeaders - pointer to valid image headers
    lppImage - pointer to LPVOID what receive allocated space base
  Return Value:
    int - error code
*/
int LdrDefaultImageAllocation(PIMAGE_NT_HEADERS32 pNtHeaders, LPVOID *lppImage, BOOL bCanReallocate)
{    
    if (IS_NULL(pNtHeaders) || IS_NULL(lppImage))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    __try
    {
        LPVOID pBase = 0;

        // Check if the image have relocations

        if (!bCanReallocate)
        {
            // If image have no relocations

            pBase = VirtualAlloc((LPVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
            if (IS_NULL(pBase))
            {
                return System::SetErrorCode(E_BASE_FAILED, true, (LPVOID)pNtHeaders->OptionalHeader.ImageBase);
            }
            goto continue_routine;
        }
        if (!FLAGS_PRESENT(pNtHeaders->OptionalHeader.DllCharacteristics, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
        {
            // If image have relocations and no "dynamic load" flag 
            // trying to allocate at preffered base

            pBase = VirtualAlloc((LPVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
            if (pBase != NULL)
                goto continue_routine;
        }

        // If image have relocations and "dynamic load" flag 
        // and allocation at preffered base failed
        // let system to select allocation base

        pBase = VirtualAlloc(NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
        if (IS_NULL(pBase))
            return System::SetErrorCode(E_VIRTUAL_FAILED, true);

continue_routine:
        *lppImage = pBase;
        return System::SetErrorCode(E_SUCCESS);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
}

/*
  Description:
    Image load and map helper.
  Arguments:
    pImage - pointer to valid image descriptor what receives mapped image descriptor
    hFile - handle to opened image file
    hMap - handle to opened image file map
  Return Value:
    int - error code
*/
int LdrHeaderCheck(PFILE_MAP pFileMap)
{
    /*
        Fields checking in accordance with:
            "Microsoft Portable Executable and Common Object File Format Specification.
             Revision 8.3 – February 6, 2013"
    */

    if (IS_NULL(pFileMap))
        return System::SetErrorCode(E_INVALID_ARGUMENT);

    DWORD dwGranularity = System::GetSystemInfo()->dwAllocationGranularity;
    DWORD dwPageSize = System::GetSystemInfo()->dwPageSize;

    __try
    {
        DWORD dwHeadersSize = 0;

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)System::MmCreateView(pFileMap, 0, sizeof(IMAGE_DOS_HEADER));
    
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return System::SetErrorCode(E_NO_DOS_HEADER, true, pFileMap->lpFileName);

        dwHeadersSize = pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);

        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)System::MmCreateView(pFileMap, pDosHeader->e_lfanew, 
                                                                               sizeof(IMAGE_NT_HEADERS));
        // Check magic
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
            return System::SetErrorCode(E_NO_PE, true, pFileMap->lpFileName);
        if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return System::SetErrorCode(E_UNKNOWN_PE, true, pFileMap->lpFileName);

        // Check main alignments
        if (pNtHeaders->OptionalHeader.ImageBase % dwGranularity)
            return System::SetErrorCode(E_BAD_ALIGNMENT, true, pFileMap->lpFileName);

        if (pNtHeaders->OptionalHeader.SectionAlignment < pNtHeaders->OptionalHeader.FileAlignment)
            return System::SetErrorCode(E_BAD_ALIGNMENT, true, pFileMap->lpFileName);
        
        if (!IS_POWER_OF_2(pNtHeaders->OptionalHeader.FileAlignment) || 
            pNtHeaders->OptionalHeader.FileAlignment < 0x200 ||
            pNtHeaders->OptionalHeader.FileAlignment > 0x10000)
            return System::SetErrorCode(E_BAD_ALIGNMENT, true, pFileMap->lpFileName);

        if (!(pNtHeaders->OptionalHeader.SectionAlignment) ||
            ((pNtHeaders->OptionalHeader.SectionAlignment) % dwPageSize))
            return System::SetErrorCode(E_BAD_ALIGNMENT, true, pFileMap->lpFileName);

        if (pNtHeaders->OptionalHeader.SizeOfHeaders > pNtHeaders->OptionalHeader.SectionAlignment || 
            pNtHeaders->OptionalHeader.SizeOfHeaders > pFileMap->dwFileSize)
            return System::SetErrorCode(E_BAD_ALIGNMENT, true, pFileMap->lpFileName);

        dwHeadersSize += pNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

        if (dwHeadersSize > pNtHeaders->OptionalHeader.SectionAlignment || 
            dwHeadersSize > pFileMap->dwFileSize)
            return System::SetErrorCode(E_BAD_ALIGNMENT, true, pFileMap->lpFileName);

        pDosHeader = (PIMAGE_DOS_HEADER)System::MmCreateView(pFileMap, 0, dwHeadersSize);
        pNtHeaders = MAKE_PTR(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pSection = MAKE_PTR(PIMAGE_SECTION_HEADER, pNtHeaders, sizeof(IMAGE_NT_HEADERS));

        // Check sections
        // they should be in ascending order and adjacent

        DWORD section = 0;
        DWORD dwVAPosition = pNtHeaders->OptionalHeader.SectionAlignment;
        DWORD dwVASize = 0;
        DWORD dwPointerToRawData = 0;
        DWORD dwSizeOfRawData = 0;

        for (section = 0; section < pNtHeaders->FileHeader.NumberOfSections; ++section, ++pSection)
        {
            if (pSection->VirtualAddress == 0)
                return System::SetErrorCode(E_INVALID_SECTION, true, section);
            if ((pSection->VirtualAddress % pNtHeaders->OptionalHeader.SectionAlignment) ||
                pSection->VirtualAddress != dwVAPosition)
                return System::SetErrorCode(E_BAD_ALIGNMENT, true, pFileMap->lpFileName);
            dwVASize = ROUND_UP(pSection->Misc.VirtualSize, pNtHeaders->OptionalHeader.SectionAlignment);
            dwPointerToRawData = ROUND_DOWN(pSection->PointerToRawData,
                                            pNtHeaders->OptionalHeader.FileAlignment);
            dwSizeOfRawData = ROUND_UP(pSection->SizeOfRawData, 
                                       pNtHeaders->OptionalHeader.FileAlignment);
            if ((dwPointerToRawData + pSection->SizeOfRawData > pFileMap->dwFileSize))
                return System::SetErrorCode(E_BAD_ALIGNMENT, true, pFileMap->lpFileName);
            dwVAPosition = pSection->VirtualAddress + dwVASize;
        }

        if (ROUND_UP(pNtHeaders->OptionalHeader.SizeOfImage, pNtHeaders->OptionalHeader.SectionAlignment) != dwVAPosition)
            return System::SetErrorCode(E_BAD_ALIGNMENT, true, pFileMap->lpFileName);

        // Check PE File header
        if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
            return System::SetErrorCode(E_MACHINE_NOT_I386, true, pFileMap->lpFileName);
        if (pNtHeaders->FileHeader.SizeOfOptionalHeader == 0)
            return System::SetErrorCode(E_NO_OPTIONAL_HEADER, true, pFileMap->lpFileName);

        // Check file header characteristics
        if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
            return System::SetErrorCode(E_NON_EXECUTABLE, true, pFileMap->lpFileName);
        if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
            return System::SetErrorCode(E_IMAGE_IS_DLL, true, pFileMap->lpFileName);
        if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE))
            return System::SetErrorCode(E_IMAGE_IS_NOT_32BIT, true, pFileMap->lpFileName);

        if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
        {
            // try to set process affinity mask
            // set mask to processor #1 for Windows XP
            // set mask to active process for >= Windows Vista

            DWORD dwMask = 1;
            while (System::GetOSVersion() >= VER_WINDOWS_VISTA)
            {
                HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
                if (IS_NULL(hKernel32))
                    break;
                DWORD dwAddress = (DWORD)GetProcAddress(hKernel32, "GetCurrentProcessorNumber");
                if (dwAddress)
                    dwMask = 1 << System::CustomCall(dwAddress, ccStdcall, 0);
                break;
            }
            if (!SetProcessAffinityMask((HANDLE)-1, dwMask))
                return System::SetErrorCode(E_AFFINITY_FAIL, true, pFileMap->lpFileName);
        }

        // Check subsystem
        if (pNtHeaders->OptionalHeader.Subsystem > IMAGE_SUBSYSTEM_WINDOWS_CUI)
            return System::SetErrorCode(E_UNSUPPORTED_SUBSYSTEM, true, pFileMap->lpFileName);
        if (pNtHeaders->OptionalHeader.Subsystem < IMAGE_SUBSYSTEM_WINDOWS_GUI)
            return System::SetErrorCode(E_UNSUPPORTED_SUBSYSTEM, true, pFileMap->lpFileName);

        // Check entry point
        if (!pNtHeaders->OptionalHeader.AddressOfEntryPoint)
            return System::SetErrorCode(E_NO_ENTRYPOINT, true, pFileMap->lpFileName);

        if (MAKE_VERSION(pNtHeaders->OptionalHeader.MajorSubsystemVersion,
            pNtHeaders->OptionalHeader.MinorSubsystemVersion) > System::GetOSVersion())
            return System::SetErrorCode(E_UNSUPPORTED_VERSION, true, pFileMap->lpFileName);

        return System::SetErrorCode(E_SUCCESS);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
}

/*
  Description:
    Maps image file
  Arguments:
    pImage - pointer to valid image descriptor what receives mapped image descriptor
    lpFileName - name of file to map
  Return Value:
    int - error code
*/
int LdrMapImage(PIMAGE_DESCRIPTOR pImage, LPCWSTR lpFileName)
{

    if (IS_NULL(pImage) || IS_NULL(lpFileName))
        return System::SetErrorCode(E_INVALID_ARGUMENT);

    FILE_MAP map;

    // Create file map and check image

    if (System::MmCreateMap(&map, lpFileName) != E_SUCCESS)
        return System::GetErrorCode(false);

    if (LdrHeaderCheck(&map) != E_SUCCESS)
    {
#ifdef _LDR_DEBUG_
        return System::GetErrorCode(false);
#else
        return System::SetErrorCode(E_NOT_A_WIN32, true, lpFileName);
#endif
    }

    __try
    {
        
        IMAGE_NT_HEADERS ntHeaders = *MAKE_PTR(PIMAGE_NT_HEADERS, map.lpView, 
                                               ((PIMAGE_DOS_HEADER)map.lpView)->e_lfanew);

        // Save data for loader reallocation if needed

        System::SetRelocationData((LPVOID)ntHeaders.OptionalHeader.ImageBase, 
                                  ntHeaders.OptionalHeader.SizeOfImage);

        // Try to reserve address space

        LPVOID lpBase = 0;
        System::MmFreeView(&map);

        ntHeaders.OptionalHeader.SizeOfImage = ROUND_UP(ntHeaders.OptionalHeader.SizeOfImage,  
                                                        ntHeaders.OptionalHeader.SectionAlignment);

        BOOL bCanReallocate = false;
        if (!FLAGS_PRESENT(ntHeaders.FileHeader.Characteristics, IMAGE_FILE_RELOCS_STRIPPED))
        {
            LPVOID lpView = System::MmCreateView(&map, 0, ntHeaders.OptionalHeader.SizeOfHeaders);
            if (IS_NULL(lpView))
                return System::GetErrorCode(false);
            PIMAGE_DESCRIPTOR pImage = LdrObtainImageDescriptor(lpView);
            if (LdrCheckDataDirectory(pImage, IMAGE_DIRECTORY_ENTRY_BASERELOC) == E_SUCCESS)
                bCanReallocate = true;
            LdrCloseImageDescriptor(pImage);
        }

        int iAllocResult = LdrDefaultImageAllocation(&ntHeaders, &lpBase, bCanReallocate);
        if (iAllocResult == E_BASE_FAILED)
        {

            // Check if space cannot be reserved due to overlapped loader and loading image spaces

            PIMAGE_DESCRIPTOR pLoader = LdrObtainImageDescriptor(GetModuleHandleW(0));
            if (IS_RANGE_OVERLAPPED_SZ((DWORD)ntHeaders.OptionalHeader.ImageBase, ntHeaders.OptionalHeader.SizeOfImage,
                                       (DWORD)pLoader->pImageBase, pLoader->pOptionalHeader->SizeOfImage))
                return System::SetErrorCode(E_LOADER_OVERLAP, true, (DWORD)ntHeaders.OptionalHeader.ImageBase);
        }
        if (iAllocResult != E_SUCCESS)
            return System::GetErrorCode(false);

        // Map image header

        LPVOID lpPosition = VirtualAlloc(lpBase, ntHeaders.OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
        LPVOID lpView = System::MmCreateView(&map, 0, ntHeaders.OptionalHeader.SizeOfHeaders);
        if (IS_NULL(lpView))
        {
            VirtualFree(lpBase, ntHeaders.OptionalHeader.SizeOfImage, MEM_DECOMMIT | MEM_RELEASE);
            return System::SetErrorCode(E_MAP_FAIL, true);
        }

        memcpy(lpPosition, lpView, ntHeaders.OptionalHeader.SizeOfHeaders);

        // Map image sections and fix some alignments

        PIMAGE_NT_HEADERS pNtHeaders = MAKE_PTR(PIMAGE_NT_HEADERS, lpPosition, 
                                                ((PIMAGE_DOS_HEADER)lpPosition)->e_lfanew);
        pNtHeaders->OptionalHeader.SizeOfImage = ROUND_UP(pNtHeaders->OptionalHeader.SizeOfImage,  
                                                          pNtHeaders->OptionalHeader.SectionAlignment);
        PIMAGE_SECTION_HEADER pSection = MAKE_PTR(PIMAGE_SECTION_HEADER, pNtHeaders, sizeof(IMAGE_NT_HEADERS));
        DWORD section = 0;
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[I]    Load sections\n    %-11s %-11s %-11s %-11s %-11s\n", L"Name", L"VA", L"VSize", L"RA", L"RSize");
#endif //_LDR_DEBUG_
        for (section = 0; section < ntHeaders.FileHeader.NumberOfSections; ++section, ++pSection)
        {
            if (pSection->VirtualAddress == 0)
                return System::SetErrorCode(E_NOT_A_WIN32, true, lpFileName);

            // Fix alignment

            pSection->PointerToRawData = ROUND_DOWN(pSection->PointerToRawData,
                                                    ntHeaders.OptionalHeader.FileAlignment);
            pSection->SizeOfRawData = ROUND_UP(pSection->SizeOfRawData,
                                                 ntHeaders.OptionalHeader.FileAlignment);
            pSection->Misc.VirtualSize = ROUND_UP(pSection->Misc.VirtualSize, 
                                                  ntHeaders.OptionalHeader.SectionAlignment);

            if (pSection->PointerToRawData + pSection->SizeOfRawData > map.dwFileSize)
                pSection->SizeOfRawData = map.dwFileSize - pSection->PointerToRawData;

#ifdef _LDR_DEBUG_
            char sectionName[9];
            sectionName[8] = 0;
            memcpy(sectionName, pSection->Name, 8);
            System::SysDbgMessage(L"    %-11S 0x%08X  0x%08X  0x%08X  0x%08X\n", sectionName, pSection->VirtualAddress, pSection->Misc.VirtualSize, pSection->PointerToRawData, pSection->SizeOfRawData);
#endif //_LDR_DEBUG_

            lpPosition = MAKE_LPVOID(lpBase, pSection->VirtualAddress);
            lpPosition = VirtualAlloc(lpPosition, pSection->Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE);
            if (IS_NULL(lpPosition))
            {
                VirtualFree(lpBase, ntHeaders.OptionalHeader.SizeOfImage, MEM_DECOMMIT | MEM_RELEASE);
                return System::SetErrorCode(E_VIRTUAL_FAILED, true);
            }

            // Copy image section

            lpView = System::MmCreateView(&map, pSection->PointerToRawData, pSection->SizeOfRawData);
            if (IS_NULL(lpView))
            {
                VirtualFree(lpBase, ntHeaders.OptionalHeader.SizeOfImage, MEM_DECOMMIT | MEM_RELEASE);
                return System::GetErrorCode(false);
            }
            memcpy(lpPosition, lpView, min(pSection->SizeOfRawData, pSection->Misc.VirtualSize));
        } // for (section = 0; section < ntHeaders.FileHeader.NumberOfSections; ++section, ++pSection)
        PIMAGE_DESCRIPTOR pModule = LdrObtainImageDescriptor(lpBase);
        pModule->dwImageFileSize = map.dwFileSize;
        System::MmFreeMap(&map);
        *pImage = *pModule;
        LdrCloseImageDescriptor(pModule);
    } // __try
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
#else
        return System::SetErrorCode(E_NOT_A_WIN32, true, lpFileName);
#endif
    }
    return System::SetErrorCode(E_SUCCESS);
}

/*
  Description:
    Set right memory access flags according to section headers
  Arguments:
    pImage - pointer to valid image descriptor
  Return Value:
    int - error code
*/
int LdrProtectSections(PIMAGE_DESCRIPTOR pImage)
{
    if (IS_NULL(pImage))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    __try
    {
        System::SetErrorCode(E_SUCCESS);
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)pImage->pSections;
        for (int section = 0; section < pImage->pFileHeader->NumberOfSections; ++section, ++pSection)
        {
            DWORD dwProtect = 0;

            // Translate flags to windows memory protection constants

            if ((pSection->Characteristics & IMAGE_SCN_MEM_WRITE) && (pSection->Characteristics & IMAGE_SCN_MEM_READ))
                dwProtect = PAGE_READWRITE;
            else if (pSection->Characteristics & IMAGE_SCN_MEM_READ)
                dwProtect = PAGE_READONLY;
            if (dwProtect == 0)
                dwProtect = PAGE_NOACCESS;
            if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                dwProtect <<= 4;

            // Commit protection options

            if (!VirtualProtect(MAKE_LPVOID(pImage->pImageBase, pSection->VirtualAddress), pSection->Misc.VirtualSize, dwProtect, &dwProtect))
            {
                System::SetErrorCode(E_PROTECT_FAIL);
#ifdef _LDR_DEBUG_
                System::SysDbgMessage(L"[I] Failed to protect \"%S\" section", pSection->Name);
#endif
            }
        }
    } // __try
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
    return System::GetErrorCode(false);
}

/*
  Description:
    Set read/write access to all sections
  Arguments:
    pImage - pointer to valid image descriptor
  Return Value:
    int - error code
*/
int LdrAllowSections(PIMAGE_DESCRIPTOR pImage)
{
    if (IS_NULL(pImage))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    __try
    {
        System::SetErrorCode(E_SUCCESS);
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)pImage->pSections;
        for (int section = 0; section < pImage->pFileHeader->NumberOfSections; ++section, ++pSection)
        {
            DWORD dwProtect = PAGE_WRITECOPY;
        
            // Commit protection options

            if (!VirtualProtect(MAKE_LPVOID(pImage->pImageBase, pSection->VirtualAddress), pSection->Misc.VirtualSize, dwProtect, &dwProtect))
            {
                System::SetErrorCode(E_PROTECT_FAIL);
#ifdef _LDR_DEBUG_
                System::SysDbgMessage(L"[I] Failed to protect \"%S\" section", pSection->Name);
#endif
            }
        }
    } // __try
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
    return System::GetErrorCode(false);
}
