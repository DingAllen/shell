#include "PEParser.h"

#define PASSWORD 0x10111101

int main() {

    LPVOID pImageBuffer = nullptr;
    TCHAR shellFileName[MAX_PATH];
    GetModuleFileName(NULL, shellFileName, MAX_PATH);
    PPEFile shell = new PEFile(shellFileName);

    WORD numberOfSections = shell->pPEHeader->NumberOfSections;
    if (strcmp(reinterpret_cast<const char *>(shell->pSectionHeaders[numberOfSections - 1].Name), ".dshell") != 0) {
        PRINTLNF("��ǰ�����ǿ�Դ���벻Ҫֱ�Ӵ򿪣���ʹ�üӿǹ��߼ӿǺ�ʹ�á�");
        system("pause");
        return 0;
    }

    DWORD sizeOfImage = shell->pOptionHeader->SizeOfImage;
    DWORD sizeOfHeaders = shell->pOptionHeader->SizeOfHeaders;

    // ����ImageBuffer������ڴ�ռ�
    pImageBuffer = malloc(shell->pOptionHeader->SizeOfImage);

    // ���ļ���ͷ������ImageBuffer��
    memcpy(pImageBuffer, shell->pFileBuffer, sizeOfHeaders);

    // ��ImageBuffer��û���õ��Ĳ���ȫ����ʼ��Ϊ0
    memset(((BYTE *) pImageBuffer) + sizeOfHeaders, 0,
           sizeOfImage - sizeOfHeaders);

    // ��ʼ����ڣ����ڱ��и����ڵ����ݿ���ImageBuffer��
    for (int i = 0; i < numberOfSections; i++) {
        memcpy((LPVOID) ((DWORD) pImageBuffer + (DWORD) shell->pSectionHeaders[i].VirtualAddress),
               (LPVOID) ((DWORD) shell->pFileBuffer + (DWORD) shell->pSectionHeaders[i].PointerToRawData),
               shell->pSectionHeaders[i].SizeOfRawData);
    }


    return 0;
}
