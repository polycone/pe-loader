/*
 * Thread local storage helper
 */

#include "loader.h"
#include "../errors.h"
#include "../system/syscalls.h"

__declspec(thread) DWORD dwEnableTlsDummy[1024];

// Piece of IMAGE_TLS_DIRECTORY
typedef struct _IMAGE_TLS_COMPARE
{
    DWORD   StartAddressOfRawData;
    DWORD   EndAddressOfRawData;
    DWORD   AddressOfIndex;             
    DWORD   AddressOfCallBacks;         
} IMAGE_TLS_COMPARE, *PIMAGE_TLS_COMPARE;

/*
  Description:
    Locates program entry of "LdrpTlsList"
  Return Value:
    LPVOID - pointer to system TLS list entry
*/
LPVOID LdrLocateTlsRecord()
{
    int (__stdcall *memcmp)(DWORD dest, LPVOID src, DWORD sz);
    memcmp = (int (__stdcall *)(DWORD, LPVOID, DWORD))System::GetSysProcAddress("memcmp");
    PPEB pPeb = NtCurrentTeb()->Peb;

    // 1. Locate heap base and size
    // 2. Scan heap for piece of IMAGE_TLS_DIRECTORY
    // 3. Found address - size of LIST_ENTRY = PIMAGE_TLS_DIRECTORY

    HANDLE hHeap = GetProcessHeap();
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(hHeap, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    DWORD dwHeapSize = mbi.RegionSize;
    PIMAGE_DESCRIPTOR pSelf = LdrObtainImageDescriptor(GetModuleHandleW(0));
    IMAGE_TLS_COMPARE tlsSourceData;
    PIMAGE_TLS_COMPARE tlsSelf = MAKE_PTR(PIMAGE_TLS_COMPARE, pSelf->pImageBase, 
                                 pSelf->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    tlsSourceData = *tlsSelf;
    DWORD dwPosition = (DWORD)hHeap;
    DWORD dwHeapEnd = dwPosition + dwHeapSize - sizeof(IMAGE_TLS_COMPARE);
    LPVOID lpEntry = NULL;
    for (; dwPosition < dwHeapEnd; dwPosition += sizeof(DWORD))
    {
        if (memcmp(dwPosition, &tlsSourceData, sizeof(IMAGE_TLS_COMPARE)) == 0)
        {
            lpEntry = (LPVOID)(dwPosition - sizeof(LIST_ENTRY));
            break;
        }
    }
    return lpEntry;
}

/*
  Description:
    Initialize TLS
  Arguments:
    pImage - pointer to valid image descriptor
    pSystemTlsEntry - pointer to a valid program TLS list entry field "tls"
  Return Value:
    int - error code
*/
int LdrInitializeTls(PIMAGE_DESCRIPTOR pImage, PIMAGE_TLS_DIRECTORY pSystemTlsEntry, BOOL bCopyData)
{
    // For the TLS support use __declspec(thread) variable once

    dwEnableTlsDummy[0] = 1;

    if (IS_NULL(pImage))
        return System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);

    // Check for TLS availability

    if (LdrCheckDataDirectory(pImage, IMAGE_DIRECTORY_ENTRY_TLS) != E_SUCCESS)
        return System::SetErrorCode(E_TLS_NOT_FOUND);

    DWORD dwTlsOffset = pImage->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    PIMAGE_TLS_DIRECTORY pNewTls = MAKE_PTR(PIMAGE_TLS_DIRECTORY, pImage->pImageBase, dwTlsOffset);

    // Fill TLS entry with appropriate values

    pSystemTlsEntry->AddressOfCallBacks = pNewTls->AddressOfCallBacks;
    DWORD dwTlsIndex = *(DWORD*)pSystemTlsEntry->AddressOfIndex;
    PTEB pTeb = NtCurrentTeb();

    // Reallocate allocated TLS memory

    if (bCopyData)
    {
        LPVOID *lppIndexPtr = (LPVOID*)((DWORD*)pTeb->ThreadLocalStoragePointer + dwTlsIndex);
        System::MmFree(*lppIndexPtr);
        *lppIndexPtr = System::MmAlloc(pNewTls->EndAddressOfRawData - pNewTls->StartAddressOfRawData, true);
        memcpy(*lppIndexPtr, pNewTls->StartAddressOfRawData, 
               pNewTls->EndAddressOfRawData - pNewTls->StartAddressOfRawData);
    }

    *(DWORD*)pNewTls->AddressOfIndex = dwTlsIndex;
    pSystemTlsEntry->AddressOfIndex = pNewTls->AddressOfIndex;
    pSystemTlsEntry->EndAddressOfRawData = pNewTls->EndAddressOfRawData;
    pSystemTlsEntry->StartAddressOfRawData = pNewTls->StartAddressOfRawData;

    // Call callbacks
    if (bCopyData && pSystemTlsEntry->AddressOfCallBacks) {
        PDWORD pCallback = (PDWORD)pSystemTlsEntry->AddressOfCallBacks;
        DWORD dwCallback = 0;
        DWORD dwBase = (DWORD)pImage->pImageBase;
        while (*pCallback)
        {
            dwCallback = *pCallback++;
            System::CustomCall(dwCallback, ccStdcall, 12, pImage->pImageBase, DLL_PROCESS_ATTACH, 0);
        }
    }
    return System::SetErrorCode(E_SUCCESS);
}
