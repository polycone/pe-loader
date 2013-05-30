/*
 * Process data patcher helper
 */

#include "loader.h"
#include "../helpers.h"
#include "../errors.h"
#include "../system/syscalls.h"

/*
  Description:
    Patch process information
  Arguments:
    pImage - pointer to a valid image descriptor
  Return Value:
    int - error code
*/
int LdrPatchProcess(PIMAGE_DESCRIPTOR pImage)
{
    __try
    {
        PPEB pPeb = NtCurrentTeb()->Peb;
        PPEB_LDR_DATA pLdrData = pPeb->pLdr;
        PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink;

        LPCWSTR lpOriginalName = Helpers::ExtractFileName(System::GetCommandLineItem(0));
        LPCWSTR lpNewName = Helpers::ExtractFileName(System::GetExecutableFileName()->Buffer);

        int result = 0;

        // Patch modules hash table

        result = LdrPatchHashTable(pLdrEntry, lpOriginalName, lpNewName);

#ifdef _LDR_DEBUG_
        if (result != E_SUCCESS)
            System::SysDbgMessage(L"[W] Unable to modify hashtable, GetModuleHandle may fail.\n");
#endif

        // Patch process parameters

        PRTL_USER_PROCESS_PARAMETERS pParameters = pPeb->lpProcessParameters;

        static WCHAR wcCurrentDir[MAX_PATH];
        static WCHAR wcCmdLine[MAX_PATH];
        static WCHAR wcFileName[MAX_PATH];
        static WCHAR wcFilePath[MAX_PATH];
        static UNICODE_STRING usFilePath;
        static UNICODE_STRING usBaseName;
        static UNICODE_STRING usCmdLine;

        Helpers::ExtractFileDirectory(System::GetExecutableFileName()->Buffer, wcCurrentDir);
        swprintf(wcCmdLine, L"\"%s\"", 4, System::GetExecutableFileName()->Buffer);
        memcpy(wcFileName, lpNewName, (Helpers::strlenW(lpNewName) + 1) * sizeof(WCHAR));
        memcpy(wcFilePath, System::GetExecutableFileName()->Buffer, (Helpers::strlenW(System::GetExecutableFileName()->Buffer) + 1) * sizeof(WCHAR));
        
        RtlInitUnicodeString(&usBaseName, wcFileName);
        RtlInitUnicodeString(&usFilePath, wcFilePath);
        RtlInitUnicodeString(&usCmdLine, wcCmdLine);

        // Set base address in peb

        pPeb->lpImageBaseAddress = pImage->pImageBase;

        // Set process image file name

        pParameters->ImagePathName = usFilePath;

        // Set process working directory

        int iResult = 1;
        iResult = SetCurrentDirectoryW(wcCurrentDir);

#ifdef _LDR_DEBUG_
        if (!iResult)
            System::SysDbgMessage(L"[W] Unable to set current directory. error: 0x%08X\n", GetLastError());
#endif

        // Set process command line, window title

        pParameters->CommandLine = usCmdLine;
        pParameters->WindowTitle = usFilePath;

        // Patch windows loader entry

        pLdrEntry->SizeOfImage = pImage->pOptionalHeader->SizeOfImage;
        pLdrEntry->ModuleBase = pImage->pImageBase;

        if (System::GetOSVersion() >= VER_WINDOWS_8)
            ((Windows8::PLDR_DATA_TABLE_ENTRY)pLdrEntry)->OriginalBase = pImage->pOptionalHeader->ImageBase;

        pLdrEntry->ModuleFileName = usFilePath;
        pLdrEntry->ModuleBaseName.Buffer = (PWSTR)Helpers::ExtractFileName(pLdrEntry->ModuleFileName.Buffer);
        pLdrEntry->ModuleBaseName.Length = (Helpers::strlenW(pLdrEntry->ModuleBaseName.Buffer) * sizeof(WCHAR)) & 0xFFFF;
        pLdrEntry->ModuleBaseName.MaximumLength = pLdrEntry->ModuleBaseName.Length + sizeof(WCHAR);
        pLdrEntry->EntryPoint = (PVOID)((DWORD)pImage->pImageBase + pImage->pOptionalHeader->AddressOfEntryPoint);

    } // __try
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }
    return System::SetErrorCode(E_SUCCESS);
}
