/*
 * Message box helper
 */

#include "message_box.h"
#include "../system/system.h"
#include "string_resource.h"

namespace Helpers
{

    /*
      Description:
        Shows critical error message box
      Arguments:
        lpText - error text
    */
    void ShowCriticalErrorBox(LPCWSTR lpText)
    {
        typedef BOOL (APIENTRY *pMessageBox)(HWND, LPCWSTR, LPCWSTR, UINT);
        HMODULE hUser32 = LoadLibraryW(L"user32.dll");
        if (hUser32 == NULL)
        {
            return;
        }
        pMessageBox MessageBox = (pMessageBox)GetProcAddress(hUser32, "MessageBoxW");
        if (MessageBox == NULL)
            return;
        WCHAR lpCaption[1024];
        Helpers::LoadStringW(System::GetHandle(), 20000, lpCaption, 1024);
        MessageBox(0, lpText, lpCaption, MB_ICONERROR);
    }

} // namespace Helpers
