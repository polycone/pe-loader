/*
 * System defenition
 */

#ifndef _SYSTEM_H_
#define _SYSTEM_H_

#include <Windows.h>
#include "dbgcl.h"
#include "errors.h"
#include "../loader/image_descriptor.h"

#define BUFFER_SIZE             1024    // Max wvsprintfW buffer size

#define ERROR_DATA_LEN          1024    // Max error data length
#define ERROR_DATA_LEN_S        1025    // ERROR_DATA_LEN + 1

#define MAX_MESSAGE_RESOURCE    512     // Max string resouce length

#ifdef _LDR_DEBUG_
#define DEBUG_PIPE_NAME         L"\\\\.\\pipe\\dbgldr"
#endif

#define VER_WINDOWS_XP               0x00050001
#define VER_WINDOWS_SERVER_2003      0x00050002
#define VER_WINDOWS_VISTA            0x00060000
#define VER_WINDOWS_7                0x00060001
#define VER_WINDOWS_8                0x00060002

#define MAKE_PTR(cast, ptr, addValue) (cast)((DWORD)(ptr) + (DWORD)(addValue))
#define MAKE_LPVOID(ptr, addValue) (MAKE_PTR(LPVOID, (ptr), (addValue)))
#define FLAGS_PRESENT(value, flags) (((value) & (flags)) == (flags))
#define IS_NULL(arg) ((arg) == NULL)
#define MAKE_VERSION(major, minor) (DWORD)(((major) << 16) | (minor))

// Check if range [a1, b1] overlaps with [a2, b2]
#define IS_RANGE_OVERLAPPED(a1, b1, a2, b2) (((b1) >= (a2)) && ((a1) <= (b2)))

// Check if range [a1, a1 + sz1] overlaps with [a2, a2 + sz2]
#define IS_RANGE_OVERLAPPED_SZ(a1, sz1, a2, sz2) (IS_RANGE_OVERLAPPED(a1, (a1) + (sz1), a2, (a2) + (sz2)))

// Check if p in [a, b]
#define IS_IN_RANGE(p, a, b) (IS_RANGE_OVERLAPPED(a, b, p, p))

// Check if p in [a, a + b]
#define IS_IN_RANGE_SZ(p, a, s) (IS_IN_RANGE(p, a, (a) + (s)))

#define IS_POWER_OF_2(x) (((x) != 0) && !((x) & ((x) - 1)))

typedef struct _IMAGE_ACTIVATION_CONTEXT
{
    HANDLE hOldActivationContext;
    HANDLE hActivationContext;
    HANDLE hFileActivationContext;
    ULONG_PTR ulFileCookie;
} IMAGE_ACTIVATION_CONTEXT, *PIMAGE_ACTIVATION_CONTEXT;

enum CallingConversion
{
    ccStdcall,
    ccCdecl
};

typedef struct _FILE_MAP
{
    HANDLE hFileMap;
    DWORD dwFileSize;
    LPVOID lpView;
    LPWSTR lpFileName;
} FILE_MAP, *PFILE_MAP;

namespace System
{

    typedef DWORD (*SYSCALL)();

    typedef struct _SYSTEM_RELOCATION_DATA
    {
        LPVOID lpReqBase;
        DWORD dwReqSize;
        LPVOID lpJumpPoint;
        IMAGE_DESCRIPTOR relocatedLoader;
    } SYSTEM_RELOCATION_DATA, *PSYSTEM_RELOCATION_DATA;

    // Program run-time environment
    typedef struct _SYSTEM 
    {
        IMAGE_DESCRIPTOR loader;                    // Loader image descriptor
        HANDLE hHeap;                               // Process heap
        HMODULE hSystemDll;                         // Pointer to ntdll
        HANDLE hPipe;                               // Debug pipe
        LPWSTR *argv;                               // Command line arguments
        int argc;                                   // Command line arguments count
        LPWSTR lpCmdW;                              // Unicode command line for new module
        LPSTR lpCmdA;                               // Ansi command line for new module
        UNICODE_STRING lpFileNameW;                 // Unicode executable name
        UNICODE_STRING lpBaseNameW;                 // Unicode module name
        UNICODE_STRING lpNtFileNameW;               // Unicode NT file name
        DWORD dwLastError;                          // Last error
        DWORD dwError;                              // Windows error code
        WCHAR lpErrorString[ERROR_DATA_LEN_S];      // Error data string
        BOOL bErrorFlag;                            // Set to 1 if error occured
        BOOL bBlockError;                           // Blocks critical error changes
        DWORD dwVersion;                            // Windows version
        DWORD dwProcessId;                          // Current process id
        SYSTEM_INFO sysInfo;                        // System information, such as granularity
        SYSTEM_RELOCATION_DATA sysRelocationData;   // System relocation data for E_BASE_FAILED
        LPVOID lpTlsDataEntry;                      // TLS data entry for loader module
    } SYSTEM, *PSYSTEM;

    // Main system functions

    int EntryPoint();
    int SysInit();
    int SysFree();

    // Callers

    DWORD SysCall(LPCSTR lpFunc, CallingConversion cc, DWORD dwStackSize, ...);
    DWORD CustomCall(DWORD dwRoutineAddress, CallingConversion cc, DWORD dwStackSize, ...);
    DWORD GetSysProcAddress(LPCSTR lpFunc);

    // Errors

    int SetErrorCode(int sysError, BOOL bMessage = false, ...);
    int GetErrorCode(BOOL bBlockError);
    void SetErrorBlock(BOOL bBlockError);
    int GetLastError();

    // Memory

    LPVOID MmAlloc(size_t size, bool zeroMem);
    bool MmFree(LPVOID lpAllocation);
    LPVOID MmReAlloc(LPVOID lpMem, size_t size, bool zeroMem);
    int MmCreateMap(PFILE_MAP pFileMap, LPCWSTR lpFileName);
    LPVOID MmCreateView(PFILE_MAP pFileMap, DWORD dwOffset, DWORD dwSize);
    void MmFreeView(PFILE_MAP pFileMap);
    void MmFreeMap(PFILE_MAP pFileMap);

    // Input/Output

    HANDLE IoOpen(LPCWSTR fileName, DWORD dwDesiredAccess, DWORD dwCreationDisposition);
    void IoClose(HANDLE hFile);

    // System variables resolvers

    LPSTR GetActiveCommandLineA();
    LPWSTR GetActiveCommandLineW();
    LPWSTR GetCommandLineItem(DWORD dwIndex);
    PUNICODE_STRING GetExecutableFileName();
    PUNICODE_STRING GetExecutableBaseName();
    DWORD GetProcessId();
    DWORD GetOSVersion();
    LPSYSTEM_INFO GetSystemInfo();
    PLDRP_TLS_ENTRY GetTlsEntry();
    PUNICODE_STRING GetExecutableNtFileName();

    // System data

    PLDR_DATA_TABLE_ENTRY GetSystemLdrTableEntry(HMODULE hModule);
    void SetRelocationData(LPVOID lpReqBase, DWORD dwReqSize);
    HMODULE GetHandle();
    PIMAGE_DESCRIPTOR GetLoader();

    // Debug

#ifdef _LDR_DEBUG_

    void SysDbgMessage(LPCWSTR lpMessage, ...);

#endif

} // namespace System

#endif // _SYSTEM_H_
