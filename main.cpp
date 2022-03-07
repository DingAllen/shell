#include "PEParser.h"

#define PASSWORD 0x10111101

int main() {

    LPVOID pImageBuffer = nullptr;
    TCHAR shellFileName[MAX_PATH];
    GetModuleFileName(NULL, shellFileName, MAX_PATH);
    auto shell = new PEFile(shellFileName);

    WORD numberOfSections = shell->pPEHeader->NumberOfSections;
    if (strcmp(reinterpret_cast<const char *>(shell->pSectionHeaders[numberOfSections - 1].Name), ".dshell") != 0) {
        PRINTLNF("��ǰ�����ǿ�Դ���벻Ҫֱ�Ӵ򿪣���ʹ�üӿǹ��߼ӿǺ�ʹ�á�");
        system("pause");
        return 0;
    }

    DWORD sizeOfFile = shell->pSectionHeaders[numberOfSections - 1].Misc.VirtualSize;
    LPVOID pEncryptedBuffer = malloc(sizeOfFile);
    memcpy_s(pEncryptedBuffer, sizeOfFile,
             reinterpret_cast<const void *const>(shell->pSectionHeaders[numberOfSections - 1].PointerToRawData),
             sizeOfFile);
    for (DWORD i = 0; i < sizeOfFile; i++) {
        *((PBYTE)pEncryptedBuffer + i) ^= PASSWORD;
    }
    delete shell;

    auto src = new PEFile(pEncryptedBuffer, sizeOfFile);
    pImageBuffer = src->GetImageBuffer();



    delete src;
    free(pImageBuffer);

    return 0;
}
