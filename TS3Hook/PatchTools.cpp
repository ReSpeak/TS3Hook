#include "main.h"
#include <Windows.h>
#include <Psapi.h>
#include <cstdio>

MODULEINFO GetModuleInfo(const LPCWSTR szModule)
{
	MODULEINFO modinfo = { nullptr, 0, nullptr };
	const HMODULE hModule = GetModuleHandle(szModule);
	if (hModule == nullptr)
		return modinfo;
	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	return modinfo;
}

SIZE_T FindPattern(const LPCWSTR module, const char* pattern, const char* mask)
{
	//Get all module related information
	const MODULEINFO mInfo = GetModuleInfo(module);

	//Assign our base and module size
	//Having the values right is ESSENTIAL, this makes sure
	//that we don't scan unwanted memory and leading our game to crash
	const SIZE_T base = reinterpret_cast<SIZE_T>(mInfo.lpBaseOfDll);
	const SIZE_T size = static_cast<SIZE_T>(mInfo.SizeOfImage);

	//Get length for our mask, this will allow us to loop through our array
	const SIZE_T patternLength = strlen(mask);

	for (SIZE_T i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		for (SIZE_T j = 0; j < patternLength && found; j++)
		{
			//if we have a ? in our mask then we have true by default, 
			//or if the bytes match then we keep searching until finding it or not
			found &= mask[j] == '?' || pattern[j] == *reinterpret_cast<char*>(base + i + j);
		}

		//found = true, our entire pattern was found
		//return the memory addy so we can write to it
		if (found)
		{
			return base + i;
		}
	}

	return NULL;
}

void PatchBytes(const PBYTE pAddress, const BYTE overwrite[], const SIZE_T dwLen)
{
	DWORD dwOldProtect, dwBkup;
	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	for (SIZE_T x = 0x0; x < dwLen; x++)
		pAddress[x] = overwrite[x];
	VirtualProtect(pAddress, dwLen, dwOldProtect, &dwBkup);
}

#ifdef ENV32
void MakeJMP(const PBYTE pAddress, const PVOID dwJumpTo, const SIZE_T dwLen)
{
	DWORD dwOldProtect, dwBkup;

	// give the paged memory read/write permissions

	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// calculate the distance between our address and our target location
	// and subtract the 5bytes, which is the size of the jmp
	// (0xE9 0xAA 0xBB 0xCC 0xDD) = 5 bytes

	const DWORD dwRelAddr = static_cast<SIZE_T>(reinterpret_cast<SIZE_T>(dwJumpTo) - reinterpret_cast<SIZE_T>(pAddress)) - 5;

	// overwrite the byte at pAddress with the jmp opcode (0xE9)

	*pAddress = 0xE9;

	// overwrite the next 4 bytes (which is the size of a DWORD)
	// with the dwRelAddr

	*reinterpret_cast<SIZE_T*>(pAddress + 0x1) = dwRelAddr;

	// overwrite the remaining bytes with the NOP opcode (0x90)
	// NOP opcode = No OPeration

	for (SIZE_T x = 0x5; x < dwLen; x++)* (pAddress + x) = 0x90;

	// restore the paged memory permissions saved in dwOldProtect

	VirtualProtect(pAddress, dwLen, dwOldProtect, &dwBkup);
}
#else
void MakeJMP(PBYTE const pAddress, const PVOID dwJumpTo, const SIZE_T dwLen)
{
	const DWORD MinLen = 14;

	if (dwLen < 14)
		return;

	BYTE stub[] =
	{
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                // jmp qword ptr [$+6]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00     // ptr
	};

	DWORD dwOld = 0;
	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOld);

	// orig 
	memcpy(stub + 6, &dwJumpTo, 8);
	memcpy(pAddress, stub, sizeof(stub));

	for (int i = MinLen; i < dwLen; i++)
		* reinterpret_cast<BYTE*>(reinterpret_cast<DWORD_PTR>(pAddress) + i) = 0x90;

	VirtualProtect(pAddress, dwLen, dwOld, &dwOld);
}
#endif