/*
 * Debug client implementation
 */

#include "dbgcl.h"
#include "../helpers.h"

HANDLE DbgInitPipe(LPCWSTR lpPipeName)
{
    HANDLE hPipe;
    int dwIter = 2;
    while (dwIter--)
    {
        hPipe = CreateFileW(lpPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY)
        {
            if (!WaitNamedPipeW(lpPipeName, 2000))
                return INVALID_HANDLE_VALUE;
        }
        else
            break;
    }
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL))
    {
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }
    return hPipe;
}

void DbgClosePipe(HANDLE hPipe)
{
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);
}

void DbgMessage(HANDLE hPipe, LPCWSTR lpMessage, ...)
{
    if (hPipe == INVALID_HANDLE_VALUE)
        return;
    DWORD dwWritten = 0;
    WCHAR pBuffer[OUTBOUND_BUFFER_SIZE + 1];
    pBuffer[OUTBOUND_BUFFER_SIZE] = 0;
    va_list va;
    va_start(va, lpMessage);
    Helpers::wvsprintfW(pBuffer, lpMessage, va);
    WriteFile(hPipe, (LPCVOID)pBuffer, (lstrlenW(pBuffer) + 1) * sizeof(WCHAR), &dwWritten, NULL);
    va_end(va);
}

void DbgMessageV(HANDLE hPipe, LPCWSTR lpMessage, va_list args)
{
    if (hPipe == INVALID_HANDLE_VALUE)
        return;
    DWORD dwWritten = 0;
    WCHAR pBuffer[OUTBOUND_BUFFER_SIZE + 1];
    pBuffer[OUTBOUND_BUFFER_SIZE] = 0;
    Helpers::wvsprintfW(pBuffer, lpMessage, args);
    WriteFile(hPipe, (LPCVOID)pBuffer, (lstrlenW(pBuffer) + 1) * sizeof(WCHAR), &dwWritten, NULL);
}

void DbgControl(HANDLE hPipe, DWORD dwOperation)
{
    if (hPipe == INVALID_HANDLE_VALUE)
        return;
    switch (dwOperation)
    {
    case DBG_CLOSE:
        DbgMessage(hPipe, L"\1");
        break;
    case DBG_CLEAR:
        DbgMessage(hPipe, L"\2");
        break;
    case DBG_DISCONNECT:
        DbgMessage(hPipe, L"\3");
        break;
    default:
        break;
    }
}
