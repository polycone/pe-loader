/*
 * Image loader functions
 */

#include <Windows.h>
#include <TlHelp32.h>
#include "loader.h"
#include "../system/system.h"
#include "../system/syscalls.h"
#include "../errors.h"

/*
  Description:
    Check parent console availability
  Return Value:
    BOOL - TRUE if parent have console
*/
bool LdrCheckParentConsole()
{
    // Get parent process id

    int pid = -1;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32);
    pid = GetCurrentProcessId();
    if(Process32First(hSnap, &pe)) 
    {
        do 
        {
            if (pe.th32ProcessID == pid) {
                pid = pe.th32ParentProcessID;
                break;
            }
        } 
        while(Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    // Open parent process

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    if (hProc == INVALID_HANDLE_VALUE)
        return false;

    // Get process PEB

    PROCESS_BASIC_INFORMATION pbi;
    if (System::SysCall("NtQueryInformationProcess", ccStdcall, 20, hProc, 0, &pbi, sizeof(pbi), 0) != 0)
        return false;

    // Get process parameters field "ConsoleHandle"

    LPVOID pProcParams = 0;
    DWORD dwReaded = 0;
    BOOL bRes = false;
    bRes = ReadProcessMemory(hProc, (PVOID)((DWORD)pbi.PebBaseAddress + FIELD_OFFSET(PEB, lpProcessParameters)), &pProcParams, 4, &dwReaded);
    if (!bRes || (dwReaded == 0))
        return false;
    bRes = ReadProcessMemory(hProc, (PVOID)((DWORD)pProcParams + FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, ConsoleHandle)), &pProcParams, 4, &dwReaded);
    if (!bRes || (dwReaded == 0))
        return false;
    if (pProcParams != 0)
        return true;
    return false;
}

/*
  Description:
    Check image data directory for availability
  Arguments:
    pImage - pointer to a valid image descriptor
    dwDataDirectory - data directory index
  Return Value:
    int - error code
*/
int LdrCheckDataDirectory(PIMAGE_DESCRIPTOR pImage, DWORD dwDataDirectory)
{
    if (dwDataDirectory > pImage->pOptionalHeader->NumberOfRvaAndSizes)
        return System::SetErrorCode(E_BAD_DIRECTORY);
    PIMAGE_DATA_DIRECTORY pDirectory = &pImage->pOptionalHeader->DataDirectory[dwDataDirectory];
    if ((pDirectory->VirtualAddress == 0) ||
        (pDirectory->Size == 0))
        return System::SetErrorCode(E_BAD_DIRECTORY);
        
    DWORD section = 0;
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)pImage->pSections;
    for (section = 0; section < pImage->pFileHeader->NumberOfSections; ++section, ++pSection)
    {
        if (IS_RANGE_OVERLAPPED_SZ(ROUND_DOWN(pSection->VirtualAddress, pImage->pOptionalHeader->SectionAlignment),
                                   min(pSection->Misc.VirtualSize, pSection->SizeOfRawData),
                                   pDirectory->VirtualAddress, 
                                   pDirectory->Size))
        {
            if (pSection->PointerToRawData != 0)
                return System::SetErrorCode(E_SUCCESS);
        }
    }

    return System::SetErrorCode(E_BAD_DIRECTORY);
}

/*
  Description:
    Check image subsystem information
    Allocates console if needed
  Arguments:
    pImage - pointer to a valid image descriptor
  Return Value:
    int - error code
*/
int LdrCheckCUI(PIMAGE_DESCRIPTOR pImage)
{        
    if (IS_NULL(pImage))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
    __try
    {
        if (pImage->pOptionalHeader->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
        {
            if (LdrCheckParentConsole())
            {
                if (!AttachConsole(ATTACH_PARENT_PROCESS))
                {
                    if (!AllocConsole())
                    {
                        return System::SetErrorCode(E_CUI_SUBSYSTEM_FAIL, true);
                    }
                }
            }
            else 
            {
                if (!AllocConsole())
                {
                    return System::SetErrorCode(E_CUI_SUBSYSTEM_FAIL, true);
                }
            }
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

/*
  Description:
    Execute the mapped image
  Arguments:
    pImage - pointer to a valid image descriptor
  Return Value:
    int - error code
*/
PIMAGE_DESCRIPTOR pExecutingImage; // global image descriptor used for some api stubs

int LdrExecuteImage(PIMAGE_DESCRIPTOR pImage)
{
    if (IS_NULL(pImage))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);

#ifdef _LDR_DEBUG_
    System::SysDbgMessage(L"[I] Preparing for executing\n");
#endif
    // Set global image descriptor pointer

    pExecutingImage = pImage;

    // Save system API

    LdrSnapApi();
        
    DWORD lpEntryPoint = MAKE_PTR(DWORD, pImage->pImageBase, pImage->pOptionalHeader->AddressOfEntryPoint);
    int errorCode = E_SUCCESS;

    // Prepare for executing
    // 1. Check for console UI and allocates the console if needed    
    // 2. Setup API
    // 3. Process relocations
    // 4. Process image imports
    // 5. Protect image sections
    // 6. Initialize TLS

#ifdef _LDR_DEBUG_
    System::SysDbgMessage(L"[I] Check for CUI\n");
#endif
    if (LdrCheckCUI(pImage) != E_SUCCESS)
        return System::GetErrorCode(true);

#ifdef _LDR_DEBUG_
    System::SysDbgMessage(L"[I] Setup API\n");
#endif
    if (LdrSetupApi() != E_SUCCESS)
        return System::GetErrorCode(true);

#ifdef _LDR_DEBUG_
    System::SysDbgMessage(L"[I] Process relocations\n");
#endif
    errorCode = LdrProcessRelocations(pImage);
    if (errorCode != E_SUCCESS && errorCode != E_RELOCATION_NOT_NEEDED)
        return System::GetErrorCode(true);

#ifdef _LDR_DEBUG_
    System::SysDbgMessage(L"[I] Process imports\n");
#endif
    if (LdrProcessImports(pImage) != E_SUCCESS)
        return System::GetErrorCode(true);

    // Continue anyway if protection fails

    LdrProtectSections(pImage);

#ifdef _LDR_DEBUG_
    System::SysDbgMessage(L"[I] Initialize TLS\n");
#endif
    errorCode = LdrInitializeTls(pImage, &System::GetTlsEntry()->Tls, true);
    if (errorCode != E_SUCCESS && errorCode != E_TLS_NOT_FOUND)
        return System::GetErrorCode(true);

    // All preparations done. Call image entrypoint

#ifdef _LDR_DEBUG_
    System::SysDbgMessage(L"[I] Detegate flow\n");
#endif

    __asm call lpEntryPoint;

    // Exit process

    __asm mov errorCode, eax;
    ExitProcess(errorCode);
}
