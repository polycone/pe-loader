#include <Windows.h>
#include "dbgsrv.h"

void OnReceive(LPCWSTR lpMessage)
{
    wprintf(lpMessage);
}

int wmain()
{
    setlocale(LC_ALL, "");
    SetConsoleTitleW(L"PE Loader Debug Server");
    if (DbgListenPipe(L"\\\\.\\pipe\\dbgldr", OnReceive) == -1)
        wprintf(L"Cannot create pipe\n");
    system("pause");
    return 0;
}
