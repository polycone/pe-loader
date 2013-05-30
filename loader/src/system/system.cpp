/*
 * Run-time system functions
 */

#include <Windows.h>
#include <Psapi.h>
#include "system.h"
#include "syscalls.h"
#include "../helpers.h"
#include "../errors.h"
#include "../loader/loader.h"

extern int SysMain(int argc, LPCWSTR *argv);

namespace System
{

    SYSTEM system;  // global main system variable

    // Variables used after loader self-relocation proceed
    // These variables use TLS due to program have access to TLS after relocation

    BOOL __declspec(thread) bRelocated = 0;            // Self-relocation flag
    PSYSTEM __declspec(thread) pSystem = &system;      // Pointer to system main variable

#ifdef _LDR_DEBUG_
    void SysDbgMessage(LPCWSTR lpMessage, ...)
    {
        va_list va;
        va_start(va, lpMessage);
        DbgMessageV(system.hPipe, lpMessage, va);
        va_end(va);
    }
#endif

    /*
      Description:
        Sets relocation information
        used to determine loader overlapping
      Arguments:
        lpReqBase - loading image base
        dwReqSize - loading image size
    */
    void SetRelocationData(LPVOID lpReqBase, DWORD dwReqSize)
    {
        system.sysRelocationData.lpReqBase = lpReqBase;
        system.sysRelocationData.dwReqSize = dwReqSize;
    }

    /*
      Description:
        Sets system last error code (plus windows last error) and return the same value
      Arguments:
        sysError - system error code
        lpErrorText - error text
      Return Value:
        int - error code
    */
    int SetErrorCode(int sysError, BOOL bMessage, ...)
    {
        system.bErrorFlag = false;
        system.dwLastError = ::GetLastError();
        if (bMessage && !system.bBlockError)
        {
            va_list va;
            va_start(va, bMessage);
            system.lpErrorString[ERROR_DATA_LEN] = 0;
            WCHAR lpMessageString[MAX_MESSAGE_RESOURCE];
            if (Helpers::LoadStringW((HINSTANCE)system.loader.pImageBase, sysError, lpMessageString, MAX_MESSAGE_RESOURCE))
            {
                if (FormatMessageW(FORMAT_MESSAGE_FROM_STRING, lpMessageString, 0, 0, 
                                   system.lpErrorString, ERROR_DATA_LEN, &va) != 0)
                {
                    system.bErrorFlag = true;
                }
            }
        }
        system.dwError = sysError;
        return sysError;
    }

    /*
      Description:
        Gets last system error code
      Arguments:
        bBlockError - block error changing
                      call SetErrorBlock(false) to unlock this
      Return Value:
        int - error code
    */
    int GetErrorCode(BOOL bBlockError)
    {
        if (bBlockError)
            system.bBlockError = true;
        return system.dwError;
    }

    /*
      Description:
        Stes error blocking mode
      Arguments:
        bBlockError - block error changing
    */
    void SetErrorBlock(BOOL bBlockError)
    {
        system.bBlockError = bBlockError;
    }

    /*
      Description:
        Gets last windows error code
      Return Value:
        int - error code
    */
    int GetLastError()
    {
        return system.dwLastError;
    }

    /*
      Description:
        Allocates memory in the process heap
      Arguments:
        size - size of memory to be allocated
        zeroMem - fill an allocated memory with zeros (default is false)
      Return Value:
        LPVOID - allocated memory pointer
    */
    LPVOID MmAlloc(size_t size, bool zeroMem = false)
    {
        HANDLE hHeap = GetProcessHeap();
        LPVOID memory = HeapAlloc(system.hHeap, (zeroMem) ? HEAP_ZERO_MEMORY : 0, size);
        if (memory == NULL)
            SetErrorCode(E_ALLOC_FAIL, true);
        return memory;
    }

    /*
      Description:
        Reallocates memory in the process heap
      Arguments:
        lpMem - pointer to allocated memory
        size - size of memory to be allocated
        zeroMem - fill an additional allocated memory with zeros (default is false)
      Return Value:
        LPVOID - reallocated memory pointer
    */
    LPVOID MmReAlloc(LPVOID lpMem, size_t size, bool zeroMem = false)
    {
        LPVOID memory = HeapReAlloc(system.hHeap, (zeroMem) ? HEAP_ZERO_MEMORY : 0, lpMem, size);
        if (memory == NULL)
            SetErrorCode(E_REALLOC_FAIL);
        return memory;
    }

    /*
      Description:
        Frees allocated memory
      Arguments:
        lpAllocation - pointer to allocated memory
      Return Value:
        bool - true if operation succeeded, false otherwise
    */
    bool MmFree(LPVOID lpAllocation)
    {
        if (IS_NULL(lpAllocation))
            return false;
        if (!HeapFree(system.hHeap, 0, lpAllocation))
            return System::SetErrorCode(E_FREE_ERROR) ? false : false;
        return true;
    }

    /*
      Description:
        Create file read-only map
      Arguments:
        pFileMap - pointer to map object (FILE_MAP)
        lpFileName - file name to map
      Return Value:
        int - error code
    */
    int MmCreateMap(PFILE_MAP pFileMap, LPCWSTR lpFileName)
    {
        if (IS_NULL(pFileMap))
            return SetErrorCode(E_INVALID_ARGUMENT, true);

        // 1. Open file in read-only mode
        // 2. Check size
        // 3. Create file mapping
        // 4. Save file name for future use

        pFileMap->hFileMap = INVALID_HANDLE_VALUE;
        pFileMap->lpView = NULL;
        HANDLE hFile = IoOpen(lpFileName, GENERIC_READ, OPEN_EXISTING);
        if (hFile == INVALID_HANDLE_VALUE)
            return GetErrorCode(false);
        DWORD dwHigh = 0;
        pFileMap->dwFileSize = GetFileSize(hFile, &dwHigh);
        if (dwHigh != 0)
            return SetErrorCode(E_FILE_TOO_BIG, true);
        pFileMap->hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, NULL);
        CloseHandle(hFile);
        if (pFileMap->hFileMap == INVALID_HANDLE_VALUE)
            return SetErrorCode(E_MAP_FAIL, true);
        DWORD dwLength = Helpers::strlenW(lpFileName) * sizeof(WCHAR);
        pFileMap->lpFileName = (LPWSTR)MmAlloc(dwLength + sizeof(WCHAR), true);
        memcpy(pFileMap->lpFileName, lpFileName, dwLength);
        return SetErrorCode(E_SUCCESS);
    }

    /*
      Description:
        Creates file map view
      Arguments:
        pFileMap - pointer to map object (FILE_MAP)
        dwOffset - file offset
        dwSize - view size
      Return Value:
        LPVOID - pointer to view
    */
    LPVOID MmCreateView(PFILE_MAP pFileMap, DWORD dwOffset, DWORD dwSize)
    {
        if (IS_NULL(pFileMap) || (dwOffset + dwSize > pFileMap->dwFileSize))
        {
            SetErrorCode(E_INVALID_ARGUMENT, true);
            return NULL;
        }

        // 1. Unmap view if exists
        // 2. Calculate real offset and size in according with system allocation parameters
        // 3. Create view

        if (!IS_NULL(pFileMap->lpView))
        {
            UnmapViewOfFile(pFileMap->lpView);
            pFileMap->lpView = NULL;
        }

        DWORD dwMapOffset = dwOffset - dwOffset % system.sysInfo.dwAllocationGranularity;
        DWORD dwMapSize = dwSize + dwOffset % system.sysInfo.dwAllocationGranularity;

        pFileMap->lpView = MapViewOfFile(pFileMap->hFileMap, FILE_MAP_READ, 0, dwMapOffset, dwMapSize);
        return (pFileMap->lpView) ? MAKE_LPVOID(pFileMap->lpView, (dwOffset) % system.sysInfo.dwAllocationGranularity) : NULL;
    }

    /*
      Description:
        Release view
      Arguments:
        pFileMap - pointer to map object (FILE_MAP)
        dwOffset - file offset
        dwSize - view size
      Return Value:
        LPVOID - pointer to view
    */
    void MmFreeView(PFILE_MAP pFileMap)
    {
        if (IS_NULL(pFileMap))
            SetErrorCode(E_INVALID_ARGUMENT, true);
        if (!IS_NULL(pFileMap->lpView))
        {
            UnmapViewOfFile(pFileMap->lpView);
            pFileMap->lpView = NULL;
        }
        SetErrorCode(E_SUCCESS);
    }

    /*
      Description:
        Frees file map
      Arguments:
        pFileMap - pointer to map object (FILE_MAP)
        dwOffset - file offset
        dwSize - view size
      Return Value:
        LPVOID - pointer to view
    */
    void MmFreeMap(PFILE_MAP pFileMap)
    {
        if (IS_NULL(pFileMap))
            SetErrorCode(E_INVALID_ARGUMENT, true);
        if (!IS_NULL(pFileMap->lpView))
            UnmapViewOfFile(pFileMap->lpView);
        if (!IS_NULL(pFileMap->hFileMap))
            CloseHandle(pFileMap->hFileMap);
        if (!IS_NULL(pFileMap->lpFileName))
            MmFree(pFileMap->lpFileName);
        SetErrorCode(E_SUCCESS);
    }

    /*
      Description:
        Template for finding new command line (function cuts first argument)
      Arguments:
        lpCommandLine - command line string of type T
      Return Value:
        <LPWCSTR/LPCSTR> - pointer to new command line
    */
    template <typename T>
    T FindNewModuleCommandLine(T lpCommandLine)
    {
        bool quotes = false;
        while (*lpCommandLine != 0)
        {
            if (*lpCommandLine == L'"')
                quotes = !quotes;
            if (!quotes && *lpCommandLine == L' ')
                break;
            ++lpCommandLine;
        }
        while (*lpCommandLine == L' ')
            ++lpCommandLine;
        return lpCommandLine;
    }

    /*
      Description:
        Converts Win32 file name to native format
      Arguments:
        lpFileName - file name to convert
        lpBuffer - buffer for converted name
        dwSize - buffer size
      Return Value:
        <LPWCSTR/LPCSTR> - pointer to new command line
    */
    bool GetNtFileName(LPCWSTR lpFileName, LPWSTR lpBuffer, DWORD dwSize)
    {

        // 1. Open file
        // 2. Create file mapping object
        // 3. Maps a view of file (1 byte)
        // 4. Query mapped file name

        HANDLE hFile = IoOpen(lpFileName, GENERIC_READ, OPEN_EXISTING);
        if (IS_NULL(hFile))
            return false;            
        DWORD dwFileSizeHi = 0;
        DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi); 
        if(dwFileSizeLo == 0 && dwFileSizeHi == 0)
            return false;

        HANDLE hFileMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 1, NULL);
        if (IS_NULL(hFileMap))
        {
            IoClose(hFile);
            return false;    
        }

        LPVOID lpMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
        if (IS_NULL(lpMem))
        {
            CloseHandle(hFileMap);
            IoClose(hFile);
            return false;    
        }

        DWORD dwWritten = GetMappedFileNameW((HANDLE)-1, lpMem, lpBuffer, dwSize);

        UnmapViewOfFile(lpMem);
        CloseHandle(hFileMap);
        IoClose(hFile);
        return (dwWritten > 0) ? true : false;
    }

    /*
      Description:
        Initializes the system environment
      Return Value:
        int - error code
    */
    int SysInit()
    {
        system.bBlockError = false;

        // Get heap, thread, system dll, TLS
        system.hHeap = GetProcessHeap();
        system.hSystemDll = GetModuleHandleW(L"ntdll.dll");
        if (system.hSystemDll == INVALID_HANDLE_VALUE)
        {
#ifdef _LDR_DEBUG_
            DbgMessage(system.hPipe, L"[E] Failed to obtain ntdll handle\n");
#endif
            return SetErrorCode(E_NO_SYSTEM_DLL, true);
        }
        system.lpTlsDataEntry = LdrLocateTlsRecord();

#ifdef _LDR_DEBUG_
        system.hPipe = DbgInitPipe(DEBUG_PIPE_NAME);
        DbgControl(system.hPipe, DBG_CLEAR);
        DbgMessage(system.hPipe, L"[I] Initializing system\n");
#endif

        // Save loader descriptor

        PIMAGE_DESCRIPTOR pLoader = LdrObtainImageDescriptor(GetModuleHandleW(0));
        system.loader = *pLoader;
        LdrCloseImageDescriptor(pLoader);

        system.dwProcessId = GetCurrentProcessId();

        // Create new command line

        LPWSTR lpCmdW = GetCommandLineW();
        LPSTR lpCmdA = GetCommandLineA();
        system.argv = Helpers::CommandLineToArgvW(lpCmdW, &system.argc);

#ifdef _LDR_DEBUG_
        DbgMessage(system.hPipe, L"[I] System command line: %s\n", lpCmdW);
#endif

        LPWSTR lpNewCmdW = FindNewModuleCommandLine(lpCmdW);
        DWORD dwLength = Helpers::strlenW(lpNewCmdW);
        system.lpCmdW = (LPWSTR)MmAlloc((dwLength + 1) * sizeof(WCHAR), true);
        memcpy(system.lpCmdW, lpNewCmdW, dwLength * sizeof(WCHAR));

        LPSTR lpNewCmdA = FindNewModuleCommandLine(lpCmdA);
        dwLength = Helpers::strlenA(lpNewCmdA);
        system.lpCmdA = (LPSTR)MmAlloc(dwLength + 1, true);
        memcpy(system.lpCmdA, lpNewCmdA, dwLength);

        // Create executing file name, base name, NT name

        int iNewArgc = 0;
        LPWSTR *lpNewArgv = NULL;
        if (Helpers::strlenW(lpNewCmdW) > 0)
        {
            lpNewArgv = Helpers::CommandLineToArgvW(lpNewCmdW, &iNewArgc);
        }

        if (iNewArgc > 0)
        {
            DWORD dwLength = Helpers::strlenW(lpNewArgv[0]);
            system.lpFileNameW.Buffer = (LPWSTR)MmAlloc((dwLength + 1) * sizeof(WCHAR), true);
            Helpers::strcpyW(system.lpFileNameW.Buffer, lpNewArgv[0]);
            RtlInitUnicodeString(&system.lpFileNameW, system.lpFileNameW.Buffer);
            system.lpBaseNameW.Buffer = (PWSTR)Helpers::ExtractFileName(system.lpFileNameW.Buffer);
            RtlInitUnicodeString(&system.lpBaseNameW, system.lpBaseNameW.Buffer);
            system.lpNtFileNameW.Buffer = (LPWSTR)MmAlloc((MAX_PATH + 1) * sizeof(WCHAR), false);
            GetNtFileName(system.lpFileNameW.Buffer, system.lpNtFileNameW.Buffer, MAX_PATH);
            RtlInitUnicodeString(&system.lpNtFileNameW, system.lpNtFileNameW.Buffer);
        }

        LocalFree(lpNewArgv);

        // Get OS info

        DWORD dwVersion = GetVersion();
        system.dwVersion = MAKE_VERSION((DWORD)(LOBYTE(LOWORD(dwVersion))), (DWORD)(HIBYTE(LOWORD(dwVersion))));

        GetSystemInfo(&system.sysInfo);

#ifdef _LDR_DEBUG_
        DbgMessage(system.hPipe, L"[I] New command line: %s\n", system.lpCmdW);
#endif

        return SetErrorCode(E_SUCCESS);
    }

    /*
      Description:
        Frees system resources
      Return Value:
        int - error code
    */
    int SysFree()
    {
        if (!IS_NULL(system.argv))
            LocalFree(system.argv);
        MmFree(system.lpCmdA);
        MmFree(system.lpCmdW);
        MmFree(system.lpFileNameW.Buffer);
        MmFree(system.lpNtFileNameW.Buffer);
#ifdef _LDR_DEBUG_
        DbgClosePipe(system.hPipe);
#endif
        return system.dwLastError;
    }

    /*
      Description:
        Obtains system function address
      Arguments:
        lpFunc - function name
      Return Value:
        DWORD - function address
    */
    DWORD GetSysProcAddress(LPCSTR lpFunc)
    {
        return (DWORD)GetProcAddress(system.hSystemDll, lpFunc);
    }

    /*
      Description:
        Calls on selected address (__stdcall)
      Arguments:
        dwRoutineAddress - function address
        dwStackSize - size of function stack (must be multiple of 4)
        args - pointer to arguments (size of arguments is dwStackSize)
      Return Value:
        DWORD - function result
    */
    DWORD CustomCallRoutine(DWORD dwRoutineAddress, CallingConversion cc, DWORD dwStackSize, va_list args)
    {
        if (dwStackSize % sizeof(LPVOID))
            return SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
        SYSCALL cFunc = (SYSCALL)dwRoutineAddress;
        if (cFunc == NULL)
            return SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
        DWORD result = 0;
        LPVOID lpTop = (LPVOID)(args);
        LPVOID lpData = MAKE_LPVOID(args, dwStackSize - sizeof(DWORD));
        while (lpData >= lpTop)
        {
        
            // push all parameters to stack

            __asm 
            {
                mov esi, lpData;
                mov esi, [esi];
                push esi;
            }
            lpData = (LPVOID)((DWORD)lpData - sizeof(LPVOID));
        }
    
        result = cFunc();

        // if function has cdecl calling conversion then clear the stack

        if (cc == ccCdecl)
            __asm add esp, dwStackSize;
        SetErrorCode(E_SUCCESS);
        return result;
    }

    /*
      Description:
        Calls on selected address (__stdcall)
      Arguments:
        dwRoutineAddress - function address
        dwStackSize - size of function stack (must be multiple of 4)
        ... - arguments
      Return Value:
        DWORD - function result
    */
    DWORD CustomCall(DWORD dwRoutineAddress, CallingConversion cc, DWORD dwStackSize, ...)
    {
        va_list args;
        va_start(args, dwStackSize);
        return CustomCallRoutine(dwRoutineAddress, cc, dwStackSize, args);
    }

    /*
      Description:
        Calls selected system function (from ntdll)
      Arguments:
        lpFunc - function name
        dwStackSize - size of function stack (must be multiple of 4)
        ... - arguments
      Return Value:
        DWORD - function result
    */
    DWORD SysCall(LPCSTR lpFunc, CallingConversion cc, DWORD dwStackSize, ...)
    {
        if (IS_NULL(lpFunc))
            return SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
        va_list args;
        va_start(args, dwStackSize);
        DWORD dwProc = GetSysProcAddress(lpFunc);
        if (IS_NULL(dwProc))
        {
#ifdef _LDR_DEBUG_
            DbgMessage(system.hPipe, L"[E] Failed to obtain \"%S\" address\n", lpFunc);
#endif
            return SetErrorCode(E_FUNCTION_NOT_FOUND, true, lpFunc);
        }
        return CustomCallRoutine(dwProc, cc, dwStackSize, args);
    }

    /*
      Description:
        Opens the file
      Arguments:
        lpFileName - file name
        dwDesiredAccess - file access
        dwCreationDisposition - disposition
      Return Value:
        HANDLE - handle of opened file
    */
    HANDLE IoOpen(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwCreationDisposition)
    {
        if (IS_NULL(lpFileName))
        {
            System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
            return INVALID_HANDLE_VALUE;
        }
        HANDLE hFile = CreateFileW(lpFileName, dwDesiredAccess, FILE_SHARE_READ, NULL, dwCreationDisposition, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            SetErrorCode(E_OPEN_FAIL, true, lpFileName);
        return hFile;
    }
    /*
      Description:
        Closes the file
      Arguments:
        hFile - file handle
      Return Value:
        HANDLE - handle of opened file
    */
    void IoClose(HANDLE hFile)
    {
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
    }

    /*
      Description:
        Finds first free memory address of specified size
      Arguments:
        dwSize - region size
      Return Value:
        LPVOID - found memory address
    */
    LPVOID SysFindFreeMemory(DWORD dwSize)
    {
        MEMORY_BASIC_INFORMATION mbi;
        mbi.BaseAddress = (LPVOID)system.sysInfo.dwAllocationGranularity;
        DWORD dwResult = 1;
        DWORD dwRealBase = 0, dwRealSize = 0;
        while (dwResult != 0)
        {
            dwResult = VirtualQuery(mbi.BaseAddress, &mbi, sizeof(mbi));
            dwRealBase = (DWORD)mbi.BaseAddress;
            if (dwRealBase % system.sysInfo.dwAllocationGranularity)
                dwRealBase = (((DWORD)mbi.BaseAddress / system.sysInfo.dwAllocationGranularity) + 1) * system.sysInfo.dwAllocationGranularity;
            dwRealSize = mbi.RegionSize - (dwRealBase - (DWORD)mbi.BaseAddress);
            if ((mbi.State == MEM_FREE) && (dwRealSize >= dwSize) &&
                (~dwRealBase >= dwSize) &&
                !IS_RANGE_OVERLAPPED_SZ(dwRealBase, dwSize, 
                                        (DWORD)system.sysRelocationData.lpReqBase, 
                                        system.sysRelocationData.dwReqSize))
            {
                break;
            }
            mbi.BaseAddress = (LPVOID)((DWORD)mbi.BaseAddress + mbi.RegionSize);
        }
        return (dwResult) ? (LPVOID)dwRealBase : (LPVOID)-1;
    }

    /*
      Description:
        Maps loader to new address
     Return Value:
        int - error code
    */
    int SysSelfRelocate()
    {
        // Map new loader image

        HANDLE hFile = IoOpen(system.argv[0], GENERIC_READ, OPEN_EXISTING);
        if (IS_NULL(hFile))
            return GetErrorCode(false);

        HANDLE hMap = CreateFileMappingW(hFile, 0, PAGE_WRITECOPY | SEC_IMAGE, 0, 0, 0);
        CloseHandle(hFile);

        if (IS_NULL(hMap))
            return SetErrorCode(E_MAP_FAIL, true);

        LPVOID lpView = MapViewOfFileEx(hMap, FILE_MAP_COPY, 0, 0, 0, 0);
        if (IS_NULL(lpView))
            return SetErrorCode(E_VIEW_FAIL, true);
    
        PIMAGE_DESCRIPTOR pLoader = LdrObtainImageDescriptor(lpView);
        if (IS_NULL(pLoader))
            return GetErrorCode(false);

        DWORD dwImageSize = pLoader->pOptionalHeader->SizeOfImage;
        LdrCloseImageDescriptor(pLoader);
        UnmapViewOfFile(lpView);

        LPVOID lpLoaderMem = SysFindFreeMemory(dwImageSize);
        if (IS_NULL(lpLoaderMem))
            return GetErrorCode(false);

        lpView = MapViewOfFileEx(hMap, FILE_MAP_COPY, 0, 0, 0, lpLoaderMem);
        if (IS_NULL(lpView))
            return GetErrorCode(false);

        ULONG dwOld = 0;
        if (!VirtualProtect(lpView, dwImageSize, PAGE_WRITECOPY, &dwOld))
            return SetErrorCode(E_ERROR, true);

        pLoader = LdrObtainImageDescriptor(lpView);
        if (IS_NULL(pLoader))
            return GetErrorCode(false);

        // 1. Process imports
        // 2. Change TLS address
        // 3. Protect sections
        // 4. Change process parameters
    
        if (LdrProcessImports(pLoader) != E_SUCCESS)
            return GetErrorCode(false);

        DWORD dwErrorCode = LdrProcessRelocations(pLoader);
        if (dwErrorCode != E_SUCCESS && dwErrorCode != E_RELOCATION_NOT_NEEDED)
            return GetErrorCode(false);

        if (LdrInitializeTls(pLoader, &GetTlsEntry()->Tls, false) != E_SUCCESS)
            return GetErrorCode(false);

        LdrProtectSections(pLoader);

        PPEB pPeb = NtCurrentTeb()->Peb;
        PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)pPeb->pLdr->InLoadOrderModuleList.Flink;

        pLdrEntry->ModuleBase = pLoader->pImageBase;
        pLdrEntry->SizeOfImage = pLoader->pOptionalHeader->SizeOfImage;
        pLdrEntry->EntryPoint = MAKE_LPVOID(pLoader->pImageBase, pLoader->pOptionalHeader->AddressOfEntryPoint);
        pPeb->lpImageBaseAddress = pLoader->pImageBase;

        system.sysRelocationData.lpJumpPoint = pLdrEntry->EntryPoint;
        system.sysRelocationData.relocatedLoader = *pLoader;

        LdrCloseImageDescriptor(pLoader);

        bRelocated = true;

        return SetErrorCode(E_SUCCESS);
    }


    /*
      Description:
        Entry point routine
      Return Value:
        int - error code (normally ExitProcess should be called)
    */
    int EntryPointRoutine() 
    {
        int returnValue = 0;

        // Initialize system

        // Check if loader was relocated

        if (bRelocated)
        {
        
            // Restore saved variables

            system = *pSystem;
            pSystem = &system;

            // Free memory

            UnmapViewOfFile(system.loader.pImageBase);

            // Change loader data

            system.loader = system.sysRelocationData.relocatedLoader;
        }
        else
        {
            if (SysInit() != E_SUCCESS)
                ExitProcess(system.dwLastError);
        }

        // Call main function

        returnValue = SysMain(system.argc, (LPCWSTR*)system.argv);
        if ((GetErrorCode(false) == E_LOADER_OVERLAP) && !bRelocated && GetOSVersion() == VER_WINDOWS_XP)
        {
            SetErrorBlock(false);

            // If loader overlaps with loading executable then trying to move loader to different location

#ifdef _LDR_DEBUG_
            DbgMessage(system.hPipe, L"[I] Loading executable overlap with loader, trying to move loader\n");
#endif //_LDR_DEBUG_

            // TODO: LOADER RELOCATION (RelocateLoader())
            if (SysSelfRelocate() == E_SUCCESS)
            {
#ifdef _LDR_DEBUG_
                DbgMessage(system.hPipe, L"[I] Loader executable moved successfully\n");
#endif //_LDR_DEBUG_
                return SetErrorCode(E_LOADER_RELOCATION);
            }
            else
            {
#ifdef _LDR_DEBUG_
                DbgMessage(system.hPipe, L"[I] Failed to move Loader\n");
#endif //_LDR_DEBUG_
            }
        } // if (System::GetErrorCode() == E_LOADER_OVERLAP)
        else if (GetErrorCode(false) == E_BASE_FAILED)
        {
#ifdef _LDR_DEBUG_
            DbgMessage(system.hPipe, L"[I] Failed to allocate image at preffered base\n");
#endif //_LDR_DEBUG_
        }

        // Show error message box if error occured

        if (system.bBlockError || system.bErrorFlag)
        {
            Helpers::ShowCriticalErrorBox(system.lpErrorString);
        }

#ifdef _LDR_DEBUG_
        DbgMessage(system.hPipe, L"[I] SysMain return code: %d\n", returnValue);
        DbgMessage(system.hPipe, L"[I] Error code: %d (0x%08X)\n", system.dwError, system.dwError);
        DbgMessage(system.hPipe, L"[I] Windows error code: %d (0x%08X)\n", system.dwLastError, system.dwLastError);
        DbgMessage(system.hPipe, L"[I] Exiting\n");
#endif //_LDR_DEBUG_

        SysFree();
        ExitProcess(returnValue);

        // Normally process ends on ExitProcess
        return returnValue;
    }

    /*
      Description:
        Entry point of the program
      Return Value:
        int - error code (normally ExitProcess should be called)
    */
    int __declspec(naked) EntryPoint()
    {
        __asm
        {
            // Call the main routine

            call EntryPointRoutine;

            // If loader was relocated - jump to relocated module

            cmp eax, E_LOADER_RELOCATION;
            jne _exit_point;
            jmp system.sysRelocationData.lpJumpPoint;

            // Normally system should call ExitProcess

        _exit_point:
            ret
        }
    }

    /*
      Description:
        Returns new (active) command line
      Return Value:
        LPSTR - pointer to active ansi command line
    */
    LPSTR GetActiveCommandLineA()
    {
        return system.lpCmdA;
    }

    /*
      Description:
        Returns new (active) command line
      Return Value:
        LPWSTR - pointer to active unicode command line
    */
    LPWSTR GetActiveCommandLineW()
    {
        return system.lpCmdW;
    }

    /*
      Description:
        Returns parameter from command line
      Arguments:
        dwIndex - parameter index
      Return Value:
        LPWSTR - pointer to unicode command line parameter
    */
    LPWSTR GetCommandLineItem(DWORD dwIndex)
    {
        if (dwIndex < (DWORD)system.argc)
            return system.argv[dwIndex];
        return NULL;
    }

    /*
      Description:
        Returns executable (extracted from command line argument) file name
      Return Value:
        PUNICODE_STRING - pointer to unicode string
    */
    PUNICODE_STRING GetExecutableFileName()
    {
        return &system.lpFileNameW;
    }

    /*
      Description:
        Returns executable (extracted from command line argument) base file name
      Return Value:
        PUNICODE_STRING - pointer to unicode string
    */
    PUNICODE_STRING GetExecutableBaseName()
    {
        return &system.lpBaseNameW;
    }

    /*
      Description:
        Returns executable (extracted from command line argument) nt file name
      Return Value:
        PUNICODE_STRING - pointer to unicode string
    */
    PUNICODE_STRING GetExecutableNtFileName()
    {
        return &system.lpNtFileNameW;
    }

    /*
      Description:
        Returns current process id
      Return Value:
        DWORD - process id
    */
    DWORD GetProcessId()
    {
        return system.dwProcessId;
    }

    /*
      Description:
        Returns current windows version
      Return Value:
        DWORD - version
    */
    DWORD GetOSVersion()
    {
        return system.dwVersion;
    }

    /*
      Description:
        Returns current windows system info
      Return Value:
        LPSYSTEM_INFO - pointer to valid system info structure
    */
    LPSYSTEM_INFO GetSystemInfo()
    {
        return &system.sysInfo;
    }

    /*
      Description:
        Returns main module TLS entry
      Return Value:
        PLDRP_TLS_ENTRY - pointer to valid system loader LDRP_TLS_ENTRY structure
    */
    PLDRP_TLS_ENTRY GetTlsEntry()
    {
        return (PLDRP_TLS_ENTRY)system.lpTlsDataEntry;
    }

    /*
      Description:
        Finds selected module in system loader modules list
      Arguments:
        hModule - handle of module to find
      Return Value:
        PLDR_DATA_TABLE_ENTRY - pointer to valid system loader LDR_DATA_TABLE_ENTRY structure
    */
    PLDR_DATA_TABLE_ENTRY GetSystemLdrTableEntry(HMODULE hModule)
    {
        PLIST_ENTRY pHead = &NtCurrentTeb()->Peb->pLdr->InLoadOrderModuleList;
        PLIST_ENTRY pEntry = pHead->Flink;
        while (pEntry != pHead)
        {
            if (((PLDR_DATA_TABLE_ENTRY)pEntry)->ModuleBase == hModule)
                return (PLDR_DATA_TABLE_ENTRY)pEntry;
            pEntry = pEntry->Flink;
        }
        return NULL;
    }

    /*
      Description:
        Returns loader handle
      Return Value:
        HMODULE - loader handle
    */
    HMODULE GetHandle()
    {
        return (HMODULE)system.loader.pImageBase;
    }

    /*
      Description:
        Returns loader image descriptor
      Return Value:
        HMODULE - loader handle
    */
    PIMAGE_DESCRIPTOR GetLoader()
    {
        return &system.loader;
    }

}
