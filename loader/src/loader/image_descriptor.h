/*
 * Image descriptor defenition
 */

#ifndef _IMAGE_DESCRIPTOR_H
#define _IMAGE_DESCRIPTOR_H

#include "ntldr.h"

// Image descriptor
typedef struct _IMAGE_DESCRIPTOR
{
    LPVOID                        pImageBase;            // Pointer to image base
    PIMAGE_DOS_HEADER            pDosHeader;            // DOS Header (MZ)
    PIMAGE_FILE_HEADER            pFileHeader;        // PE File Header
    PIMAGE_OPTIONAL_HEADER32    pOptionalHeader;    // PE Optional Header
    LPVOID                        pSections;            // Pointer to sections
    DWORD                        dwImageFileSize;    // Image file size
} IMAGE_DESCRIPTOR, *PIMAGE_DESCRIPTOR;

#endif // _IMAGE_DESCRIPTOR_H
