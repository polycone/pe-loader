#include "dbgsrv.h"

int DbgListenPipe(LPCWSTR lpPipeName, OnMessageReceive onReceive)
{
    WCHAR pBuffer[INBOUND_BUFFER_SIZE + 1];
    pBuffer[INBOUND_BUFFER_SIZE] = 0;
    BOOL bStop = false;
    DWORD dwBytesRead = 0; 
    BOOL bSuccess = false;
    while (!bStop)
    {
        HANDLE hPipe = CreateNamedPipeW(lpPipeName, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | 
                                        PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
                                        0, INBOUND_BUFFER_SIZE * sizeof(WCHAR), 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE)
            return -1;
        if (ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED))
        {
            while (true)
            {
                bSuccess = ReadFile(hPipe, pBuffer, INBOUND_BUFFER_SIZE * sizeof(WCHAR), &dwBytesRead, NULL);
                if (!bSuccess || dwBytesRead == 0)
                {
                    CloseHandle(hPipe);
                    break;
                }
                if (pBuffer[0] == 1)
                {
                    CloseHandle(hPipe);
                    bStop = true;
                    break;
                }
                if (pBuffer[0] == 3)
                {
                    CloseHandle(hPipe);
                    break;
                }
                else if (pBuffer[0] == 2)
                    system("cls");
                else if (onReceive)
                    onReceive(pBuffer);
            }
        }
        else
        {
            CloseHandle(hPipe);
        }
    }
    return 0;
}
