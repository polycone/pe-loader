#ifndef _DBGSRV_H_
#define _DBGSRV_H_

#include <Windows.h>
#include <string>

#define INBOUND_BUFFER_SIZE        1024

typedef void (*OnMessageReceive)(LPCWSTR lpMessage);

int DbgListenPipe(LPCWSTR lpPipeName, OnMessageReceive onReceive);

#endif
