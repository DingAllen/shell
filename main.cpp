#include "PEParser.h"

#define PASSWORD 0x10111101

bool UnloadShell(HANDLE ProcHnd, unsigned long BaseAddr) {

    typedef unsigned long (__stdcall *pfZwUnmapViewOfSection)(unsigned long, unsigned long);
    pfZwUnmapViewOfSection ZwUnmapViewOfSection = nullptr;
    bool res = FALSE;
    HMODULE m = LoadLibrary("ntdll.dll");
    if (m) {
        ZwUnmapViewOfSection = (pfZwUnmapViewOfSection) GetProcAddress(m, "ZwUnmapViewOfSection");

        if (ZwUnmapViewOfSection)
            res = (ZwUnmapViewOfSection((unsigned long) ProcHnd, BaseAddr) == 0);  //ȡ��ӳ��Ŀ����̵��ڴ�
        FreeLibrary(m);
    }
    return res;
}

LPVOID AllocShellZone(HANDLE shellProcess, PPEFile shell, PPEFile src) {

    if (shell->pOptionHeader->ImageBase == 0 || shell->pOptionHeader->SizeOfImage == 0 ||
        src->pOptionHeader->ImageBase == 0 || src->pOptionHeader->SizeOfImage == 0) {

        return nullptr;
    }

    LPVOID p = nullptr;
    p = VirtualAllocEx(shellProcess, reinterpret_cast<LPVOID>(src->pOptionHeader->ImageBase),
                       src->pOptionHeader->SizeOfImage,
                       MEM_RESERVE | MEM_COMMIT,
                       PAGE_EXECUTE_READWRITE);
    if (p != nullptr) return p;
    if (src->pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress &&
        src->pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {

        p = VirtualAllocEx(shellProcess, nullptr,
                           src->pOptionHeader->SizeOfImage,
                           MEM_RESERVE | MEM_COMMIT,
                           PAGE_EXECUTE_READWRITE);
        if (p != nullptr) {
            src->changeImageBase((DWORD) p);
        }
    }
    return p;
}

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
        *((PBYTE) pEncryptedBuffer + i) ^= PASSWORD;
    }

    auto src = new PEFile(pEncryptedBuffer, sizeOfFile);
    pImageBuffer = src->GetImageBuffer();

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi;
    si.cb = sizeof(si);

    GetModuleFileName(nullptr, shellFileName, MAX_PATH);
    CreateProcess(
            nullptr,                 // name of executable module
            shellFileName,                  // command line string
            nullptr,                // SD
            nullptr,                // SD
            FALSE,                    // handle inheritance option
            CREATE_SUSPENDED,        // creation flags
            nullptr,                   // new environment block
            nullptr,                // current directory name
            &si,                    // startup information
            &pi                // process information
    );

    CONTEXT contx;
    contx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &contx);

    // ��ȡ��ڵ�
    DWORD dwEntryPoint = contx.Eax;

    // ��ȡImageBase
    char *baseAddress = (CHAR *) contx.Ebx + 8;

    DWORD shellImageBase = 0;

    ReadProcessMemory(pi.hProcess, baseAddress, &shellImageBase, 4, NULL);


    UnloadShell(pi.hProcess, shellImageBase);

    LPVOID p = AllocShellZone(pi.hProcess, shell, src);
    if (p == nullptr) {
        PRINTLNF("�ڿ��з����µ��ڴ�ռ�ʧ�ܣ�");
        CloseHandle(pi.hProcess);
        system("pause");
        return 0;
    }

    delete shell;
    delete src;
    free(pImageBuffer);

    return 0;
}
