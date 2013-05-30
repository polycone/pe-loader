/*
 * Windows system API stubs/wrappers
 */

#include "api_stubs.h"
#include "../system/system.h"

#include "../errors.h"
#include "ntldr.h"
#include "loader.h"

#define BOOL_STRING(value) ((value)) ? L"true" : L"false"

SystemApi::SYSCALL_POINTERS_SNAP SysCallSnap; // System calls snap holder

// Some defines for debug output support

#ifdef _LDR_DEBUG_
#define LdrSetExportAddressEx(pImage, lpName, lpNewAddress, dwCode) \
        dwCode = LdrSetExportAddress(pImage, lpName, lpNewAddress); \
        System::SysDbgMessage(L"[I] Setup API \"%S\": %s (%d)\n", (lpName), ((dwCode) == E_SUCCESS) ? L"ok" : L"fail", (dwCode))
#else
#define LdrSetExportAddressEx(pImage, lpName, lpNewAddress, dwCode) \
        dwCode = LdrSetExportAddress(pImage, lpName, lpNewAddress)
#endif

#ifdef _LDR_DEBUG_
#define LdrSetImportAddressEx(pImage, lpLib, lpName, lpAddress, dwCode) \
        dwCode = LdrSetImportAddress(pImage, lpLib, lpName, lpAddress);\
        System::SysDbgMessage(L"[I] Setup import \"%S\": %s (%d)\n", (lpName), ((dwCode) == E_SUCCESS) ? L"ok" : L"fail", (dwCode))
#else
#define LdrSetImportAddressEx(pImage, lpLib, lpName, lpAddress, dwCode) \
        dwCode = LdrSetImportAddress(pImage, lpLib, lpName, lpAddress)
#endif

/*
  Description:
    Snap system call addresses
  Return Value:
    int - error code
*/
int LdrSnapApi()
{
    HMODULE hSystemDll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

    if (IS_NULL(hSystemDll) || IS_NULL(hKernel32))
        return System::SetErrorCode(E_MODULE_NOT_FOUND, true, L"ntdll.dll");

    SysCallSnap.NtQueryInformationProcess = (DWORD)GetProcAddress(hSystemDll, "NtQueryInformationProcess");
    SysCallSnap.NtQuerySystemInformation = (DWORD)GetProcAddress(hSystemDll, "NtQuerySystemInformation");
    SysCallSnap.NtQueryVirtualMemory = (DWORD)GetProcAddress(hSystemDll, "NtQueryVirtualMemory");

    SysCallSnap.GetCommandLineA = (DWORD)GetProcAddress(hKernel32, "GetCommandLineA");
    SysCallSnap.GetCommandLineW = (DWORD)GetProcAddress(hKernel32, "GetCommandLineW");
    SysCallSnap.ExitProcess = (DWORD)GetProcAddress(hKernel32, "ExitProcess");

    for (int i = 0; i < (sizeof(SysCallSnap) / sizeof(DWORD)); ++i)
        if (IS_NULL(*MAKE_PTR(PDWORD, &SysCallSnap, i * sizeof(DWORD))))
            return System::SetErrorCode(E_SNAP_ERROR);

    return System::SetErrorCode(E_SUCCESS);
}

/*
  Description:
    Setup system API stubs
  Return Value:
    int - error code
*/
int LdrSetupApi()
{
    DWORD dwErrorCode = 0;
    PIMAGE_DESCRIPTOR pKernel = LdrObtainImageDescriptor(GetModuleHandleA("kernel32.dll"));
    PIMAGE_DESCRIPTOR pKernelBase = LdrObtainImageDescriptor(GetModuleHandleA("kernelbase.dll"));
    PIMAGE_DESCRIPTOR pSystemDll = LdrObtainImageDescriptor(GetModuleHandleA("ntdll.dll"));
    PIMAGE_DESCRIPTOR pPsapi = LdrObtainImageDescriptor(GetModuleHandleA("psapi.dll"));
    if (IS_NULL(pKernel))
        return System::SetErrorCode(E_MODULE_NOT_FOUND, true, L"kernel32.dll");
    if (IS_NULL(pSystemDll))
        return System::SetErrorCode(E_MODULE_NOT_FOUND, true, L"ntdll.dll");
    if (IS_NULL(pPsapi))
        return System::SetErrorCode(E_MODULE_NOT_FOUND, true, L"psapi.dll");

    // Replace kernel32 API

    LdrSetExportAddressEx(pKernel, "ExitProcess", SystemApi::ExitProcess, dwErrorCode);
    LdrSetExportAddressEx(pKernel, "GetCommandLineA", SystemApi::GetCommandLineA, dwErrorCode);
    LdrSetExportAddressEx(pKernel, "GetCommandLineW", SystemApi::GetCommandLineW, dwErrorCode);

    // Replace native API

    LdrSetExportAddressEx(pSystemDll, "NtQueryInformationProcess", SystemApi::NtQueryInformationProcess, dwErrorCode);
    LdrSetExportAddressEx(pSystemDll, "NtQuerySystemInformation", SystemApi::NtQuerySystemInformation, dwErrorCode);
    LdrSetExportAddressEx(pSystemDll, "NtQueryVirtualMemory", SystemApi::NtQueryVirtualMemory, dwErrorCode);

    // Replace native links in kernel32.dll / kernelbase.dll (>= Windows Vista)

    LdrSetImportAddressEx(pKernel, "ntdll.dll", "NtQueryInformationProcess", SystemApi::NtQueryInformationProcess, dwErrorCode);
    LdrSetImportAddressEx(pKernel, "ntdll.dll", "NtQuerySystemInformation", SystemApi::NtQuerySystemInformation, dwErrorCode);
    LdrSetImportAddressEx(pKernel, "ntdll.dll", "NtQueryVirtualMemory", SystemApi::NtQueryVirtualMemory, dwErrorCode);

    if (!IS_NULL(pKernelBase))    // For Windows XP compatibility
    {
        LdrSetImportAddressEx(pKernelBase, "ntdll.dll", "NtQueryInformationProcess", SystemApi::NtQueryInformationProcess, dwErrorCode);
        LdrSetImportAddressEx(pKernelBase, "ntdll.dll", "NtQuerySystemInformation", SystemApi::NtQuerySystemInformation, dwErrorCode);
        LdrSetImportAddressEx(pKernelBase, "ntdll.dll", "NtQueryVirtualMemory", SystemApi::NtQueryVirtualMemory, dwErrorCode);
    }

    // Replace native links in psapi.dll for Windows XP/Vista

    if (System::GetOSVersion() <= VER_WINDOWS_VISTA)
    {
        LdrSetImportAddressEx(pPsapi, "ntdll.dll", "NtQueryInformationProcess", SystemApi::NtQueryInformationProcess, dwErrorCode);
        LdrSetImportAddressEx(pPsapi, "ntdll.dll", "NtQuerySystemInformation", SystemApi::NtQuerySystemInformation, dwErrorCode);
        LdrSetImportAddressEx(pPsapi, "ntdll.dll", "NtQueryVirtualMemory", SystemApi::NtQueryVirtualMemory, dwErrorCode);
    }

    // Set these dlls time to zero to force bound image import table refresh

    System::GetSystemLdrTableEntry((HMODULE)pKernel->pImageBase)->TimeDateStamp = 0;
    if (!IS_NULL(pKernelBase))
        System::GetSystemLdrTableEntry((HMODULE)pKernelBase->pImageBase)->TimeDateStamp = 0;
    System::GetSystemLdrTableEntry((HMODULE)pSystemDll->pImageBase)->TimeDateStamp = 0;
    System::GetSystemLdrTableEntry((HMODULE)pPsapi->pImageBase)->TimeDateStamp = 0;
    
    LdrProtectSections(pKernel);
    LdrCloseImageDescriptor(pKernel);
    LdrProtectSections(pKernelBase);
    LdrCloseImageDescriptor(pKernelBase);
    LdrProtectSections(pSystemDll);
    LdrCloseImageDescriptor(pSystemDll);
    LdrProtectSections(pPsapi);
    LdrCloseImageDescriptor(pPsapi);

    return System::SetErrorCode(E_SUCCESS);
}

namespace SystemApi
{

/*
  ExitProcess API stub
*/
void WINAPI ExitProcess(UINT uCode)
{
#if defined(_LDR_DEBUG_) && defined(_LDR_DEBUG_VERBOSE_)
    System::SysDbgMessage(L"[H] ExitProcess\n");
    System::SysDbgMessage(L"        uCode: %d\n", uCode);
#endif
    System::CustomCall(SysCallSnap.ExitProcess, ccStdcall, 4, uCode);
}

/*
  GetCommandLineA API stub
*/
LPSTR WINAPI GetCommandLineA()
{
#if defined(_LDR_DEBUG_) && defined(_LDR_DEBUG_VERBOSE_)
    System::SysDbgMessage(L"[-H] GetCommandLineA\n");
#endif
    return System::GetActiveCommandLineA();
}

/*
  GetCommandLineW API stub
*/
LPWSTR WINAPI GetCommandLineW()
{
#if defined(_LDR_DEBUG_) && defined(_LDR_DEBUG_VERBOSE_)
    System::SysDbgMessage(L"[-H] GetCommandLineW\n");
#endif
    return System::GetActiveCommandLineW();
}

/*
  NtQueryInformationProcess API stub
  do the real query and 
  fill fields with appropriate values if needed
*/
NTSTATUS WINAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                          PVOID ProcessInformation, ULONG ProcessInformationLength,
                                          PULONG ReturnLength)
{
#if defined(_LDR_DEBUG_) && defined(_LDR_DEBUG_VERBOSE_)
    System::SysDbgMessage(L"[-H] NtQueryInformationProcess\n");
    System::SysDbgMessage(L"        ProcessInformationClass: %d\n", ProcessInformationClass);
#endif
    NTSTATUS ntStatus = System::CustomCall(SysCallSnap.NtQueryInformationProcess, ccStdcall, 20, ProcessHandle, ProcessInformationClass,
                                           ProcessInformation, ProcessInformationLength, ReturnLength);

    PROCESS_BASIC_INFORMATION pPbi;
    NTSTATUS ntResult = System::CustomCall(SysCallSnap.NtQueryInformationProcess, ccStdcall, 20, ProcessHandle, ProcessBasicInformation,
                                           &pPbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

    if ((ntResult == 0) && 
        (ntStatus == 0) && 
        ((ProcessHandle == (HANDLE)-1 || 
        pPbi.UniqueProcessId == (HANDLE)System::GetProcessId()) &&
        !IS_NULL(ProcessInformation)))
    {

        // Change real executable file name
        // Change executable params

        if (ProcessInformationClass == ProcessImageFileNameWin32)
            *(PUNICODE_STRING)ProcessInformation= *System::GetExecutableFileName();
        else if (ProcessInformationClass == ProcessImageFileName)
            *(PUNICODE_STRING)ProcessInformation = *System::GetExecutableNtFileName();
        else if (ProcessInformationClass == ProcessImageInformation)
        {
            PSECTION_IMAGE_INFORMATION iInf = (PSECTION_IMAGE_INFORMATION)ProcessInformation;
            iInf->TransferAddress = MAKE_PTR(PVOID, pExecutingImage->pImageBase, pExecutingImage->pOptionalHeader->AddressOfEntryPoint);
            iInf->CheckSum = pExecutingImage->pOptionalHeader->CheckSum;
            iInf->DllCharacteristics = pExecutingImage->pOptionalHeader->DllCharacteristics;
            iInf->ImageFileSize = pExecutingImage->dwImageFileSize;
            iInf->ImageCharacteristics = pExecutingImage->pFileHeader->Characteristics;
            iInf->SubSystemType = pExecutingImage->pOptionalHeader->Subsystem;
            iInf->SubSystemMajorVersion = pExecutingImage->pOptionalHeader->MajorSubsystemVersion;
            iInf->SubSystemMinorVersion = pExecutingImage->pOptionalHeader->MinorSubsystemVersion;
        }
    }
#if defined(_LDR_DEBUG_) && defined(_LDR_DEBUG_VERBOSE_)
    System::SysDbgMessage(L"        procId: %d\n", pPbi.UniqueProcessId);
    System::SysDbgMessage(L"        result: 0x%08X\n", ntStatus);
#endif
    return ntStatus;
}

/*
  NtQuerySystemInformation API stub
  do the real query and 
  fill fields with appropriate values if needed
*/
NTSTATUS WINAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
                                         ULONG SystemInformationLength, PULONG ReturnLength)
{
#if defined(_LDR_DEBUG_) && defined(_LDR_DEBUG_VERBOSE_)
    System::SysDbgMessage(L"[-H] NtQuerySystemInformation\n");
    System::SysDbgMessage(L"        SystemInformationClass: %d\n", SystemInformationClass);
#endif
    NTSTATUS ntStatus = System::CustomCall(SysCallSnap.NtQuerySystemInformation, ccStdcall, 16, SystemInformationClass, SystemInformation,
                                           SystemInformationLength, ReturnLength);
    if ((SystemInformationClass == SystemProcessInformation || 
         SystemInformationClass == SystemExtendedProcessInformation) &&
         !IS_NULL(SystemInformation) &&
         (ntStatus == 0))
    {
        PSYSTEM_PROCESS_INFORMATION pSpiHead = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION pSpi = pSpiHead;
        HANDLE CurentProcessId = (HANDLE)System::GetProcessId();
        while (true)
        {
            if (pSpi->UniqueProcessId == CurentProcessId)
            {
                pSpi->ImageName = *System::GetExecutableBaseName();
            }
            if (pSpi->NextEntryOffset == NULL)
                break;
            pSpi = MAKE_PTR(PSYSTEM_PROCESS_INFORMATION, pSpi, pSpi->NextEntryOffset); 
        }
    }
#if defined(_LDR_DEBUG_) && defined(_LDR_DEBUG_VERBOSE_)
    System::SysDbgMessage(L"        result: 0x%08X\n", ntStatus);
#endif
    return ntStatus;
}

/*
  NtQueryVirtualMemory API stub
  do the real query and 
  fill fields with appropriate values if needed
  shows that the mapped image has SEC_IMAGE flag
  (used for exception handler validation in _ValidateEH3RN)
*/
NTSTATUS WINAPI NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, 
                                     MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation,
                                     SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
#if defined(_LDR_DEBUG_) && defined(_LDR_DEBUG_VERBOSE_)
    System::SysDbgMessage(L"[-H] NtQueryVirtualMemory\n");
    System::SysDbgMessage(L"        BaseAddress: 0x%08X\n", BaseAddress);
    System::SysDbgMessage(L"        MemoryInformationClass: %d\n", MemoryInformationClass);
#endif
    NTSTATUS ntStatus = System::CustomCall(SysCallSnap.NtQueryVirtualMemory, ccStdcall, 24, ProcessHandle, BaseAddress,
                                           MemoryInformationClass, MemoryInformation,
                                           MemoryInformationLength, ReturnLength);
    PROCESS_BASIC_INFORMATION pPbi;
    NTSTATUS ntResult = System::CustomCall(SysCallSnap.NtQueryInformationProcess, ccStdcall, 20, ProcessHandle, ProcessBasicInformation,
                                           &pPbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if ((ntResult == 0) &&
        (ntStatus == 0) &&
        ((ProcessHandle == (HANDLE)-1 || pPbi.UniqueProcessId == (HANDLE)System::GetProcessId()) &&
        !IS_NULL(MemoryInformation)))
    {
        if (MemoryInformationClass == MemoryBasicInformation)
        {
            if (((DWORD)BaseAddress >= (DWORD)pExecutingImage->pImageBase) && 
                ((DWORD)BaseAddress <= MAKE_PTR(DWORD, pExecutingImage->pImageBase, 
                                       pExecutingImage->pOptionalHeader->SizeOfImage)))
            {
                PMEMORY_BASIC_INFORMATION32 pMbi = (PMEMORY_BASIC_INFORMATION32)MemoryInformation;
                pMbi->Type = MEM_IMAGE;
            }
        }
    }
#if defined(_LDR_DEBUG_) && defined(_LDR_DEBUG_VERBOSE_)
    System::SysDbgMessage(L"        procId: %d\n", pPbi.UniqueProcessId);
    System::SysDbgMessage(L"        result: 0x%08X\n", ntStatus);
#endif
    return ntStatus;
}

} // namespace SystemApi
