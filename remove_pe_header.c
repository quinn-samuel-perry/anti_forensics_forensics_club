/*
* It removes the windows header from memory
* It could stop people from seeing it in memory, could not
* src: some defcon conference
*/
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

void main()
{
	BOOL bProtect = FALSE;
	DWORD dwBaseAddress = (DWORD)GetModuleHandle(NULL);
	DWORD dwProtect = 0;
	DWORD dwSizeOfHeaders = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwBaseAddress;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);
	
	//Check for MZ header
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return;
	}
	//check for PE header
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return;
	}
	
	//get size of headers so we know how much to zero
	if (pNtHeader->FileHeader.SizeOfOptionalHeader) {
		dwSizeOfHeaders = pNtHeader->OptionalHeader.SizeOfHeaders;

		//make page writeable
		bProtect = VirtualProtect((LPVOID)dwBaseAddress, dwSizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwProtect);
		if (bProtect == FALSE) {
			return;
		}

		//zero out headers
		RtlZeroMemory((LPVOID)dwBaseAddress, dwSizeOfHeaders);

		bProtect = VirtualProtect((LPVOID)dwBaseAddress, dwSizeOfHeaders, dwProtect, &dwProtect);
		if (bProtect == FALSE) {
			return;
		}
	}

	printf("lol\n");
	//return 0;
}

