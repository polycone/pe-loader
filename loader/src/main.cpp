/*
 * Main function
 */

#include "system/system.h"
#include "loader/loader.h"
#include "helpers/strings.h"
#include "helpers/opendialog.h"
#include "system/syscalls.h"

/*
  Description:
    Gets executing image file name
  Arguments:
    plpFileName - valid pointer to unicode string
    argc - arguments count (cmd)
    argv - argument variables (cmd)
  Return Value:
    BOOL - true if image file name was obtained via dialog
           false if via command line
*/
BOOL GetImageFileName(LPWSTR *plpFileName, int argc, LPCWSTR *argv)
{
    __try
    {
        *plpFileName = (LPWSTR)System::MmAlloc(MAX_PATH * sizeof(WCHAR), true);

        // 1. Check for argv[1] availability
        // 2. If not available start open dialog

        if (argc > 1)
            if (argv[1])
            {
                Helpers::strcpyW(*plpFileName, argv[1]);
                return false;
            }
        if (!Helpers::ExecuteOpenFileDialog(L"Windows Image File (*.exe)\0*.exe\0All Files\0*.*\0", *plpFileName, MAX_PATH))
        {
            System::MmFree(*plpFileName);
            *plpFileName = NULL;
        }
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif
        return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
    }    
}

/*
  Description:
    Restarts loader if open dialog was showed 
  Arguments:
    plpFileName - valid pointer to unicode string
    argc - arguments count (cmd)
    argv - argument variables (cmd)
  Return Value:
    int - error code
*/
int CheckImageFileName(LPWSTR *lpFileName, int argc, LPCWSTR *argv)
{
    if (GetImageFileName(lpFileName, argc, argv))
    {
        if (!*lpFileName)
            return System::SetErrorCode(E_FILE_IS_NULL, true);

#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[I] Configure to launch: %s\n", *lpFileName);
        System::SysDbgMessage(L"[I] Disconnecting from pipe\n");
        System::SysDbgMessage(L"\3"); // DBG_DISCONNECT
#endif

        // If open dialog was showed program have to reload to free libraries

        __try
        {
            STARTUPINFOW sInfo;
            PROCESS_INFORMATION pInfo;
            memset(&sInfo, 0, sizeof(STARTUPINFOW));
            memset(&pInfo, 0, sizeof(PROCESS_INFORMATION));
            sInfo.cb = sizeof(STARTUPINFOW);
            LPWSTR lpCmd = (LPWSTR)System::MmAlloc(BUFFER_SIZE, true);
            swprintf(lpCmd, L"\"%s\" \"%s\"", 8, argv[0], *lpFileName);

            // Create loader process with new command line

            CreateProcessW(0, lpCmd, 0, 0, false, 0, 0, 0, &sInfo, &pInfo);
            System::MmFree(*lpFileName);
            System::MmFree(lpCmd);
            return System::SetErrorCode(E_FORWARDED);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
#ifdef _LDR_DEBUG_
            System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif
            System::MmFree(*lpFileName);
            return System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
        }
    }
    return System::SetErrorCode(E_SUCCESS);
}

/*
  Description:
    System main function (runs after SysInit and befor SysFree)
  Arguments:
    argc - arguments count (cmd)
    argv - argument variables (cmd)
  Return Value:
    int - error code
*/
int SysMain(int argc, LPCWSTR *argv)
{    
    LPWSTR lpFileName = NULL;
    int errorCode = 0;
    IMAGE_ACTIVATION_CONTEXT hActCtx;
    IMAGE_DESCRIPTOR image;

    // Obtain file name of image to execute

    if (CheckImageFileName(&lpFileName, argc, argv) != E_SUCCESS)
        return (System::GetErrorCode(false) == E_FORWARDED) ? E_FORWARDED : System::GetErrorCode(true);

    if (!lpFileName)
        return System::SetErrorCode(E_FILE_IS_NULL, true);

    // Map selected image

    if (LdrMapImage(&image, lpFileName) != E_SUCCESS)
        return System::GetErrorCode(true);

    // Patch process

    if (LdrPatchProcess(&image) != E_SUCCESS)
        return System::GetErrorCode(true);

    // Set process activation context

    errorCode = LdrSetDefaultActivationContext(&image, &hActCtx);
    if (errorCode != E_SUCCESS && errorCode != E_NO_MANIFEST)
        return System::GetErrorCode(true);

    // Execute loaded and mapped image

    errorCode = LdrExecuteImage(&image);

    // Free resources and restore process activation context
    // Normally ExitProcess should be called before

    LdrRestoreDefaultActivationContext(&hActCtx);
    System::MmFree(lpFileName);
    return errorCode;
}
