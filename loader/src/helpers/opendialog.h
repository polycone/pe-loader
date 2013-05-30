/*
 * Open dialog helpers defenition
 */

#ifndef _OPENDIALOG_HELPER_H_
#define _OPENDIALOG_HELPER_H_

#include <Windows.h>

namespace Helpers
{

    LPWSTR ExecuteOpenFileDialog(LPCWSTR lpFilter, LPWSTR lpFileName, DWORD lpFileNameSize);

}

#endif // _OPENDIALOG_HELPER_H_
