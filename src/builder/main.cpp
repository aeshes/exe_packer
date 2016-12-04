#include <windows.h>
#include <stdlib.h>
#include "stub.h"
#include "xtea.h"
#include "define.h"

#define ALIGN_DOWN(x, align) (x & ~(align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x)
#define MakePtr(Type, Base, Offset) ((Type)(DWORD(Base) + (DWORD)(Offset)))


void EncryptImage(LPBYTE pImage, DWORD dwImageSize);

/* Read file from disc to buffer. Returns the file size in dwFileSize variable */
LPVOID FileToMem(LPCSTR szFileName, DWORD *dwFileSize)
{
    HANDLE hFile = NULL;
    DWORD dwRead = 0;
    DWORD dwSize = 0;
    LPVOID pBuffer = NULL;
 
    hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile)
    {
        dwSize = GetFileSize(hFile, NULL);
        if (dwSize > 0) 
        {
            pBuffer = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
            if (pBuffer)
            {
                ReadFile(hFile, pBuffer, dwSize, &dwRead, NULL);
            }
        }
        CloseHandle(hFile);
    }
	*dwFileSize = dwSize;
    return pBuffer;
}

/* Patches (in stub) the size and offset of PE-file appended to .text section */
void PatchStub(PBYTE pStub, DWORD dwImageSize, DWORD dwImageOffset)
{
	for (int i = 0; i < stub_size; i++)
		if (*(DWORD *)(&pStub[i]) == 0xDEADFADE)
			*(DWORD *)(&pStub[i]) = dwImageSize;
		else if (*(DWORD *)(&pStub[i]) == 0xDEADC0DE)
			*(DWORD *)(&pStub[i]) = dwImageOffset;
}

int main(int argc, char *argv[])
{
	DWORD dwImageSize = 0;
	DWORD dwWritten = 0;
	HANDLE hFile = NULL;
	LPBYTE pImage = (LPBYTE) FileToMem(argv[1], &dwImageSize);	/* Read file to mem */
	/* Allocate memory for stub and appended PE-image */
	LPBYTE pStub = (LPBYTE) VirtualAlloc(NULL, stub_size + dwImageSize + 0x1000, MEM_COMMIT, PAGE_READWRITE);

	/* Encrypt PE-image in memory */
	EncryptImage(pImage, dwImageSize);

	/* Copy stub to allocated free buffer */
	CopyMemory(pStub, stub, stub_size);
	/* Find first section (it is the only .text section */
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) pStub;
	PIMAGE_NT_HEADERS nt = MakePtr(PIMAGE_NT_HEADERS, pStub, dos->e_lfanew);
	PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(nt);
	PIMAGE_SECTION_HEADER text = IMAGE_FIRST_SECTION(nt);

	/* Fill marked variables in stub that will contain size of PE-image and its offset in .text section */
	PatchStub(pStub, dwImageSize, nt->OptionalHeader.ImageBase + text->VirtualAddress + text->Misc.VirtualSize);

	/* Append PE-image to the end of .text section */
	CopyMemory(&pStub[text->PointerToRawData + text->Misc.VirtualSize], pImage, dwImageSize);
	/* Assign new raw and virtual size of .text section */
	text->SizeOfRawData = ALIGN_UP(text->Misc.VirtualSize + dwImageSize, nt->OptionalHeader.FileAlignment);
	text->Misc.VirtualSize += dwImageSize;
	nt->OptionalHeader.SizeOfImage = ALIGN_UP(text->Misc.VirtualSize + text->VirtualAddress, nt->OptionalHeader.FileAlignment);
	
	/* Calculate size of file that contains stub and appended PE-image */
	DWORD dwNewFileSize = pSections->SizeOfRawData + text->PointerToRawData;

	/* Write buffer (stub + payload) to disc */
	hFile = CreateFile(TEXT("loader.exe"),
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile != NULL)
	{
		WriteFile(hFile, pStub, dwNewFileSize, &dwWritten, NULL);
	}
}

void EncryptImage(LPBYTE pImage, DWORD dwImageSize)
{
	DWORD blocks = dwImageSize / BLOCK_SIZE;
	for (int i = 0; i < blocks; i++)
	{
		EncryptBlock(64, (uint32_t *)pImage, key);
		pImage += BLOCK_SIZE;
	}
}