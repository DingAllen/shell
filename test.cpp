#include "PEParser.h"

int main() {

    auto shell = new PEFile("shell.exe");
    auto src = new PEFile("111.exe");
    shell->RaiseANewSection(".dshell", 0x60000020, src->sizeOfBuffer);
    auto p = (LPVOID) ((DWORD) shell->pFileBuffer +
                       shell->pSectionHeaders[shell->pPEHeader->NumberOfSections - 1].PointerToRawData);
    memcpy_s(p, shell->pSectionHeaders[shell->pPEHeader->NumberOfSections - 1].SizeOfRawData,
             src->pFileBuffer,
             src->sizeOfBuffer);
    shell->Save("H:\\22_s.exe");

    return 0;
}