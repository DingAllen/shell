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
            res = (ZwUnmapViewOfSection((unsigned long) ProcHnd, BaseAddr) == 0);  //取消映射目标进程的内存
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
        PRINTLNF("当前程序是壳源，请不要直接打开，请使用加壳工具加壳后使用。");
        system("pause");
        delete shell;
        free(pImageBuffer);
        return 0;
    }

    DWORD sizeOfFile = shell->pSectionHeaders[numberOfSections - 1].Misc.VirtualSize;
    LPVOID pEncryptedBuffer = malloc(sizeOfFile);
    memcpy_s(pEncryptedBuffer, sizeOfFile,
             (LPVOID) ((DWORD) shell->pFileBuffer +
                       shell->pSectionHeaders[numberOfSections - 1].PointerToRawData),
             sizeOfFile);
//    for (DWORD i = 0; i < sizeOfFile; i++) {
//        *((PBYTE) pEncryptedBuffer + i) ^= PASSWORD;
//    }
    auto src = new PEFile(pEncryptedBuffer, sizeOfFile);

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

    // 获取ImageBase
    char *baseAddress = (CHAR *) contx.Ebx + 8;

    DWORD shellImageBase = 0;

    ReadProcessMemory(pi.hProcess, baseAddress, &shellImageBase, 4, nullptr);

    UnloadShell(pi.hProcess, shellImageBase);

    LPVOID p = AllocShellZone(pi.hProcess, shell, src);
    if (p == nullptr) {
        PRINTLNF("在壳中分配新的内存空间失败！");
        system("pause");
        TerminateProcess(pi.hProcess, -1);
        delete shell;
        delete src;
        free(pImageBuffer);
        return 0;
    }

    WriteProcessMemory(pi.hProcess, baseAddress, &p, 4, nullptr);

    if (!WriteProcessMemory(pi.hProcess, p, src->GetImageBuffer(), src->pOptionHeader->SizeOfImage, nullptr)) {

        PRINTLNF("往壳空间中塞入源程序失败！");
        system("pause");
        TerminateProcess(pi.hProcess, -1);
        delete shell;
        delete src;
        free(pImageBuffer);
        return 0;
    }
    contx.Eax = (DWORD) p + src->pOptionHeader->AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &contx);
    ResumeThread(pi.hThread);

    delete shell;
    delete src;
    free(pImageBuffer);
    CloseHandle(pi.hThread);

    return 0;
}
