/*
 * Debug client defenition
 */

#ifndef _DBGCL_H_
#define _DBGCL_H_

#include <Windows.h>

#define OUTBOUND_BUFFER_SIZE        1024

#define DBG_CLOSE                        1
#define DBG_CLEAR                        2
#define DBG_DISCONNECT                    3

HANDLE DbgInitPipe(LPCWSTR lpPipeName);
void DbgClosePipe(HANDLE hPipe);
void DbgMessage(HANDLE hPipe, LPCWSTR lpMessage, ...);
void DbgMessageV(HANDLE hPipe, LPCWSTR lpMessage, va_list args);
void DbgControl(HANDLE hPipe, DWORD dwOperation);

#endif // _DBGCL_H_
