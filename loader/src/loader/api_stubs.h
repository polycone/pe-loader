/*
 * Windows API stubs defenition
 */

#ifndef _APISTUBS_H_
#define _APISTUBS_H_

#include <Windows.h>

#include "ntldr.h"

namespace SystemApi
{

    // Windows API snap

    typedef struct _SYSCALL_POINTERS_SNAP
    {

        DWORD NtQuerySystemInformation;
        DWORD NtQueryInformationProcess;
        DWORD NtQueryVirtualMemory;
        DWORD ExitProcess;
        DWORD GetCommandLineA;
        DWORD GetCommandLineW;

    } SYSCALL_POINTERS_SNAP, *PSYSCALL_POINTERS_SNAP;

    // Windows API stubs

    LPSTR WINAPI GetCommandLineA();

    LPWSTR WINAPI GetCommandLineW();

    void WINAPI ExitProcess(UINT uCode);

    NTSTATUS WINAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                              PVOID ProcessInformation, ULONG ProcessInformationLength,
                                              PULONG ReturnLength);

    NTSTATUS WINAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
                                             ULONG SystemInformationLength, PULONG ReturnLength);

    NTSTATUS WINAPI NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, 
                                         MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation,
                                         SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

} // namespace SystemApi

extern SystemApi::SYSCALL_POINTERS_SNAP SysCallSnap;

#endif // _APISTUBS_H_
