/*
 * Command string helpers defenition
 */

#ifndef _CMD_HELPER_H_
#define _CMD_HELPER_H_

#include <Windows.h>

namespace Helpers
{

    LPWSTR* WINAPI CommandLineToArgvW(LPCWSTR lpCmdline, int* numargs);

}

#endif // _CMD_HELPER_H_
