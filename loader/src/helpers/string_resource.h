/*
 * String resource helper defenition
 */

#ifndef _STRING_RES_HELPER_H_
#define _STRING_RES_HELPER_H_

#include <Windows.h>

namespace Helpers
{

    int WINAPI LoadStringW(HINSTANCE instance, UINT resource_id, LPWSTR buffer, INT buflen);

}

#endif // _STRING_RES_HELPER_H_
