/*
 * Global program error defenition
 */

#ifndef _ERRORS_H_
#define _ERRORS_H_

#define E_ERROR                         -1        // Error
#define E_SUCCESS                       0         // Success
#define E_ALLOC_FAIL                    1         // Allocation failed
#define E_OPEN_FAIL                     2         // CreateFile error
#define E_EXCEPTION                     3         // Excception occured
#define E_MAP_FAIL                      4         // CreateFileMapping error
#define E_VIEW_FAIL                     5         // MapViewOfFile error
#define E_BASE_FAILED                   10        // Failed to allocate image at base address
#define E_VIRTUAL_FAILED                11        // Failed to allocate virtual memory
#define E_RELOCATION_NOT_NEEDED         13        // Relocation isn't needed
#define E_UNKNOWN_RELOC                 14        // Unknown relocation type
#define E_LIBRARY_FAIL                  15        // Load library fail
#define E_NO_IMPORT                     17        // Image has no import data
#define E_PROTECT_FAIL                  18        // Failed to protect virtual memory
#define E_NO_SYSTEM_DLL                 20        // No system DLL (ntdll) found
#define E_FREE_ERROR                    21        // Failed to free heap memory
#define E_NO_EXPORT                     22        // Image contains no export data
#define E_NO_EXPORT_NAMES               23        // Image export contains no names
#define E_NO_ACCESS                     25        // No memory access
#define E_NO_EXPORT_PROC                26        // Image has no function with target name
#define E_NO_ACTIVATION_CONTEXT         27        // Cannot create an activation context
#define E_NO_MANIFEST                   29        // Image has no manifest

#define E_CUI_SUBSYSTEM_FAIL            31        // Failed to initialize CUI subsystem
#define E_HASH_ERROR                    32        // RtlHashUnicodeString fail
#define E_HASH_HEAD_NOT_FOUND           33        // Failed to find hash table head
#define E_INVALID_ARGUMENT              34        // Invalid parameter
#define E_MODULE_NOT_FOUND              35        // Failed to obtain module handle
#define E_FUNCTION_NOT_FOUND            36        // Failed to obtain import function address
#define E_FUNCTION_NOT_FOUND_ORD        24        // Failed to obtain import function address (for ordinals)
#define E_FILE_IS_NULL                  37        // Failed to start loader, beacause source file path is null
#define E_FORWARDED                     38        // Loader have to forward himself
#define E_REALLOC_FAIL                  39        // Failed to reallocate memory

#define E_MOVED_FREE_FAIL               40        // Failed to free old loader memory if loader was relocated
#define E_LOADER_RELOCATION             41        // Loader needs to relocate

#define E_THREAD_EXIT_CODE_FAIL         50        // Failed to get thread exit code
#define E_CREATE_THREAD_FAIL            51        // Failed to create thread

#define E_FILE_TOO_BIG                  55        // File is bigger than 2GB

#define E_HOOK_FAIL                     60        // Failed to hook system api

#define E_INVALID_SECTION               65        // PE Image has an invalid section

#define E_BAD_DIRECTORY                 70        // Invalid data directory

#define E_NO_DOS_HEADER                 100       // Image has no MZ DOS header
#define E_NO_PE                         101       // Image has no PE header
#define E_MACHINE_NOT_I386              102       // Image can be launched only on i386-like
#define E_NO_OPTIONAL_HEADER            103       // Image has no optional PE header
#define E_NON_EXECUTABLE                104       // Image is non executable
#define E_IMAGE_IS_DLL                  105       // Attempt to load dll image
#define E_IMAGE_IS_NOT_32BIT            106       // Image is not 32-bit
#define E_AFFINITY_FAIL                 107       // Image can be run only on single-processor machine, but set process affinity fails
#define E_UNKNOWN_PE                    108       // Unknown PE magic
#define E_NO_ENTRYPOINT                 109       // Image has no entry point
#define E_BAD_ALIGNMENT                 110       // Image alignment errors
#define E_UNSUPPORTED_VERSION           111       // Image OS version is greater than the current OS
#define E_UNSUPPORTED_SUBSYSTEM         112       // Unsupported image subsystem
#define E_LOADER_OVERLAP                113       // Image overlaps with loader

#define E_NOT_A_WIN32                   150       // Image is not an application for Win32

#define E_RELOCATION_NOT_FOUND          200       // Image has no relocations

#define E_TLS_NOT_FOUND                 300       // Image has no tls

#define E_NO_ORIGINAL_THUNK             400       // Image has no original thunk data
#define E_INVALID_IMPORT_NAME           401       // Image bound directory refs to invalid image
#define E_IMPORT_NOT_FOUND              402       // Defined import (lib!func) not found

#define E_SNAP_ERROR                    500       // Failed to snap ntdll functions

#define E_UNSUPPORTED_SYSTEM            600       // Unsupported Windows Version
#define E_ACCESS_DENIED                 601       // Access denied

#endif // _ERRORS_H_
