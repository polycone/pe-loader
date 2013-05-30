/*
 * Loader assembly defenition
 */

#ifndef _LOADER_H_
#define _LOADER_H_

#include <Windows.h>
#include "image_descriptor.h"
#include "../system/system.h"

typedef struct _TLS_ENTRY
{
    LPVOID lpImageBase;
    IMAGE_TLS_DIRECTORY Tls;
} TLS_ENTRY, *PTLS_ENTRY;

#define ROUND_DOWN(value, align) (((value) / (align)) * (align))
#define ROUND_UP(value, align) (ROUND_DOWN(value, align) + (((value) % (align) ? 1 : 0) * (align)))

/* image_descriptor.cpp */

PIMAGE_DESCRIPTOR LdrObtainImageDescriptor(LPVOID lpImage);
bool LdrCloseImageDescriptor(PIMAGE_DESCRIPTOR pImage);
PIMAGE_DESCRIPTOR LdrObtainImageDescriptor(LPVOID lpImage);

/* dependencies.cpp */

void LdrAllowImageDirectoryAccess(PIMAGE_DESCRIPTOR pImage, DWORD dwDataDirectory);
int LdrSetExportAddress(PIMAGE_DESCRIPTOR pImage, LPCSTR lpName, LPVOID lpAddress);
int LdrProcessImports(PIMAGE_DESCRIPTOR pImage);
int LdrSetImportAddress(PIMAGE_DESCRIPTOR pImage, LPCSTR lpLibName, LPCSTR lpFuncName, LPVOID lpAddress);
int LdrAllowSections(PIMAGE_DESCRIPTOR pImage);

/* relocations.cpp */

int LdrProcessRelocations(PIMAGE_DESCRIPTOR pModule, DWORD dwCustomDelta = -1);

/* image_mapper.cpp */

int LdrMapImage(PIMAGE_DESCRIPTOR lpImage, LPCWSTR lpFileName);
int LdrProtectSections(PIMAGE_DESCRIPTOR lpImage);

/* activation_context.cpp */

int LdrSetDefaultActivationContext(PIMAGE_DESCRIPTOR pImage, PIMAGE_ACTIVATION_CONTEXT pActivationContext);
int LdrRestoreDefaultActivationContext(PIMAGE_ACTIVATION_CONTEXT pActivationContext);

/* process_patcher.cpp */

int LdrPatchProcess(PIMAGE_DESCRIPTOR lpImage);

/* tls_support.cpp */

LPVOID LdrLocateTlsRecord();
int LdrInitializeTls(PIMAGE_DESCRIPTOR pImage, PIMAGE_TLS_DIRECTORY pSystemTlsEntry, BOOL bCopyData);

/* api_stubs.cpp */

int LdrSnapApi();
int LdrSetupApi();
int LdrRestoreApi();

/* hash_patcher.cpp */

int LdrPatchHashTable(PLDR_DATA_TABLE_ENTRY pLdrEntry, LPCWSTR lpOriginalName, LPCWSTR lpNewName);

/* loader.cpp */

int LdrInitialize();
int LdrCheckCUI(PIMAGE_DESCRIPTOR pImage);
int LdrExecuteImage(PIMAGE_DESCRIPTOR pModule);
int LdrCheckDataDirectory(PIMAGE_DESCRIPTOR pImage, DWORD dwDataDirectory);

/* globals */

extern PIMAGE_DESCRIPTOR pExecutingImage;    // Executing image descriptor, used by system API stubs

#endif //_LOADER_H_
