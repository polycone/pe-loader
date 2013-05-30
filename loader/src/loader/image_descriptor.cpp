/*
 * Image descriptor functions
 */

#include "loader.h"
#include "../errors.h"

/*
  Description:
    Allocate image descriptor
  Return Value:
    PIMAGE_DESCRIPTOR - pointer to image descriptor if success
                        NULL otherwise
*/
PIMAGE_DESCRIPTOR LdrCreateImageDescriptor()
{
    return (PIMAGE_DESCRIPTOR)System::MmAlloc(sizeof(IMAGE_DESCRIPTOR), true);
}

/*
  Description:
    Free image descriptor
  Return Value:
    bool - true if success
           false if memory cannot be free (See System::GetLastError)
*/
bool LdrCloseImageDescriptor(PIMAGE_DESCRIPTOR pImage)
{
    return System::MmFree((LPVOID)pImage);
}

/*
  Description:
    Obtains image descriptor for vaild loaded image
  Arguments:
    pImage - pointer to memory, which contains loaded image
  Return Value:
    PIMAGE_DESCRIPTOR - pointer to the image descriptor
*/
PIMAGE_DESCRIPTOR LdrObtainImageDescriptor(LPVOID pImageBase)
{
    if (IS_NULL(pImageBase))
    {
        System::SetErrorCode(E_INVALID_ARGUMENT, true, __FUNCTIONW__);
        return NULL;
    }
    PIMAGE_DESCRIPTOR pImage = LdrCreateImageDescriptor();
    if (IS_NULL(pImage))
        return NULL;
    __try
    {
        pImage->pImageBase = pImageBase;
        pImage->pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
        LPVOID lpPosition = MAKE_LPVOID(pImageBase, pImage->pDosHeader->e_lfanew + sizeof(DWORD));
        pImage->pFileHeader = (PIMAGE_FILE_HEADER)lpPosition;
        lpPosition = MAKE_LPVOID(lpPosition, sizeof(IMAGE_FILE_HEADER));
        pImage->pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)lpPosition;
        pImage->pSections = MAKE_LPVOID(lpPosition, sizeof(IMAGE_OPTIONAL_HEADER32));
        pImage->dwImageFileSize = 0;
        return pImage;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _LDR_DEBUG_
        System::SysDbgMessage(L"[X] Exception in %s [%s line %d]\n", __FUNCTIONW__, __FILEW__, __LINE__);
#endif //_LDR_DEBUG_
        System::SetErrorCode(E_EXCEPTION, true, __FUNCTIONW__);
        LdrCloseImageDescriptor(pImage);
        return NULL;
    }
}
