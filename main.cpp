#include "PEParser.h"

#define PASSWORD 0x10111101

int main() {

    LPVOID pImageBuffer = nullptr;
    TCHAR shellFileName[MAX_PATH];
    GetModuleFileName(NULL, shellFileName, MAX_PATH);
    PPEFile shell = new PEFile(shellFileName);

    WORD numberOfSections = shell->pPEHeader->NumberOfSections;
    if (strcmp(reinterpret_cast<const char *>(shell->pSectionHeaders[numberOfSections - 1].Name), ".dshell") != 0) {
        PRINTLNF("当前程序是壳源，请不要直接打开，请使用加壳工具加壳后使用。");
        system("pause");
        return 0;
    }

    DWORD sizeOfImage = shell->pOptionHeader->SizeOfImage;
    DWORD sizeOfHeaders = shell->pOptionHeader->SizeOfHeaders;

    // 申请ImageBuffer所需的内存空间
    pImageBuffer = malloc(shell->pOptionHeader->SizeOfImage);

    // 把文件的头部读到ImageBuffer中
    memcpy(pImageBuffer, shell->pFileBuffer, sizeOfHeaders);

    // 将ImageBuffer还没有用到的部分全部初始化为0
    memset(((BYTE *) pImageBuffer) + sizeOfHeaders, 0,
           sizeOfImage - sizeOfHeaders);

    // 开始处理节，将节表中各个节的内容拷到ImageBuffer中
    for (int i = 0; i < numberOfSections; i++) {
        memcpy((LPVOID) ((DWORD) pImageBuffer + (DWORD) shell->pSectionHeaders[i].VirtualAddress),
               (LPVOID) ((DWORD) shell->pFileBuffer + (DWORD) shell->pSectionHeaders[i].PointerToRawData),
               shell->pSectionHeaders[i].SizeOfRawData);
    }


    return 0;
}
