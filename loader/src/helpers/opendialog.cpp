/*
 * Open dialog helper
 */
 
#include "opendialog.h"
#include "../system/syscalls.h"

namespace Helpers
{

    /*
      Description:
        Execute windows open file dialog window
      Arguments:
        lpFilter - dialog filter ("Descriptopn \0 mask \0", ex.: "Text File\0*.txt\0")
        lpFileName - string which receive selected file name
        lpFileNameSize - size of lpFileName string
      Return Value:
        LPWSTR - error code
    */
    LPWSTR ExecuteOpenFileDialog(LPCWSTR lpFilter, LPWSTR lpFileName, DWORD lpFileNameSize)
    {
        OPENFILENAMEW dlgOpen;
        memset(&dlgOpen, 0, sizeof(OPENFILENAMEW));
        dlgOpen.lStructSize = sizeof(OPENFILENAMEW);
        dlgOpen.hInstance = GetModuleHandle(NULL);
        dlgOpen.nMaxFile = lpFileNameSize;
        dlgOpen.lpstrInitialDir = NULL;
        dlgOpen.lpstrFile = lpFileName;
        dlgOpen.lpstrFile[0] = 0;
        dlgOpen.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
        dlgOpen.lpstrFilter = lpFilter;
        typedef BOOL (APIENTRY *pGOFNW)(LPOPENFILENAMEW);
        HMODULE hComDlg = LoadLibraryW(L"Comdlg32.dll");
        if (hComDlg == NULL)
            return NULL;
        pGOFNW GetOpenFileNameW = (pGOFNW)GetProcAddress(hComDlg, "GetOpenFileNameW");
        if (GetOpenFileNameW == NULL)
            return NULL;
        if (!GetOpenFileNameW(&dlgOpen))
            return NULL;
        else
            return lpFileName;
    }

} // namespace Helpers
