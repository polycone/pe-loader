/*
 * System calls defenition
 */

#ifndef _SYSCALLS_H_
#define _SYSCALLS_H_

#include "system.h"

#define strcpy(dest, src) (System::SysCall("strcpy", ccCdecl, 8, dest, src))
#define memcpy(dest, src, size) (System::SysCall("memcpy", ccCdecl, 12, dest, src, size))
#define memset(dst, val, size) (System::SysCall("memset", ccCdecl, 12, dst, val, size))
#define RtlInitUnicodeString(dest, src) (System::SysCall("RtlInitUnicodeString", ccStdcall, 8, dest, src))
#define RtlHashUnicodeString(String, CaseInSensitive, HashAlgorithm, HashValue) (System::SysCall("RtlHashUnicodeString", ccStdcall, 16, String, CaseInSensitive, HashAlgorithm, HashValue))
#define swprintf(dest, fmt, argLen, ...) (System::SysCall("swprintf", ccCdecl, 8 + (argLen), (dest), (fmt), ##__VA_ARGS__))

#endif // _SYSCALLS_H_
