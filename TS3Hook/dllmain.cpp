// dllmain.cpp : Defines the entry point for the DLL application.
#include "main.h"
#include "base64.h"
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <Psapi.h>

#define REBASE(A) (A  + dwModuleBase)

BOOL APIENTRY DllMain(HMODULE hModule, const DWORD ul_reason_for_call, LPVOID lpReserved)
{
	DWORD dwModuleBase;
	DWORD modSize;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		// + 13
		const auto match = FindPattern(L"ts3client_win32.exe", "\x8B\x4F\x3C\x6A\x00\xFF\x77\x44\xFF\x77\x40\x8B\x01\x57\x56\xFF\x50\x10", "xxxxxxxxxxxxxxxxxx");
		if (match != NULL)
		{
			printf("Found packet dispatch: %X\n", match);
		}
		else
		{
			printf("Packet dispatcher not found, aborting");
			return FALSE;
		}

		in_packet_hook_return = match + 13 + 5;
		MakeJMP((PBYTE)(match + 13), in_packet_hook, 5);


		CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)IdleLoop, nullptr, NULL, nullptr);
		break;

		dwModuleBase = (DWORD)GetModuleHandle(L"ts3client_win32.exe");
		printf("ModBase: %X\n", dwModuleBase);

		modSize = GetModuleSize(L"ts3client_win32.exe");
		printf("ModSize: %i\n", modSize);

		//const char* ctr_encrypt_pat = "51 53 55 56 8B 35 ?? ?? ?? ?? 8B E9";

		//auto ctr_encrypt_ptr = findPattern((PBYTE)dwModuleBase, (PBYTE)dwModuleBase + modSize, ctr_encrypt_pat);
		//printf("A ctr_encrypt: %X\n", ctr_encrypt_ptr);

		ctr_decrypt_rebase = REBASE(ctr_decrypt);
		ctr_encrypt_rebase = REBASE(ctr_encrypt);
		decrypt_hook_return_rebase = REBASE(decrypt_hook_return);
		encrypt_hook_return_rebase = REBASE(encrypt_hook_return);
		//ecc_import_hook_return_rebase = REBASE(ecc_import) + 0x10;
		//printf("RETJMP: %X\n", ecc_import_hook_return_rebase);

		printf("ctr_decrypt_rebase: %X\n", ctr_decrypt_rebase);
		printf("ctr_encrypt_rebase: %X\n", ctr_encrypt_rebase);
		printf("REBASE(call_to_ctr_decrypt): %X\n", REBASE(call_to_ctr_decrypt));
		printf("REBASE(call_to_ctr_encrypt): %X\n", REBASE(call_to_ctr_encrypt));

		MakeJMP((PBYTE)(REBASE(call_to_ctr_decrypt)), decrypt_hook, 5);
		MakeJMP((PBYTE)(REBASE(call_to_ctr_encrypt)), encrypt_hook, 5);
		//MakeJMP((PBYTE)(REBASE(ecc_import) + 0x0A), ecc_import_hook, 6);
		//printf("FUNCPOS: %X\n", (DWORD)ptr_ecc_hook);
		//MakeJMP((PBYTE)((DWORD)ptr_ecc_hook) + 0x12, (void*)ecc_import_hook_return_rebase, 5);

		// 74 0B jz      short loc_7A6C0E
		// to
		// EB 0B jmp     short loc_7A6C0E
		//Patch((PBYTE)(REBASE(skip_compress_patch)), jmpdata, 1);

		CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)IdleLoop, nullptr, NULL, nullptr);
		break;

		//case DLL_THREAD_ATTACH:
		//case DLL_THREAD_DETACH:
		//case DLL_PROCESS_DETACH:
		//	break;
	}
	return TRUE;
}

void printBase64(const unsigned char* data, const unsigned long len)
{
	const auto outlen = 2 * len + 6;
	const auto outbuf = new unsigned char[outlen];
	const auto bdata = base64_encode(data, len);
	std::cout << "Import: " << bdata << std::endl;
	delete[] outbuf;
}

void MakeJMP(BYTE* pAddress, void* dwJumpTo, const DWORD dwLen)
{
	DWORD dwOldProtect, dwBkup, dwRelAddr;

	// give the paged memory read/write permissions

	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// calculate the distance between our address and our target location
	// and subtract the 5bytes, which is the size of the jmp
	// (0xE9 0xAA 0xBB 0xCC 0xDD) = 5 bytes

	dwRelAddr = (DWORD)((DWORD)dwJumpTo - (DWORD)pAddress) - 5;

	// overwrite the byte at pAddress with the jmp opcode (0xE9)

	*pAddress = 0xE9;

	// overwrite the next 4 bytes (which is the size of a DWORD)
	// with the dwRelAddr

	*((DWORD *)(pAddress + 0x1)) = dwRelAddr;

	// overwrite the remaining bytes with the NOP opcode (0x90)
	// NOP opcode = No OPeration

	for (DWORD x = 0x5; x < dwLen; x++) *(pAddress + x) = 0x90;

	// restore the paged memory permissions saved in dwOldProtect

	VirtualProtect(pAddress, dwLen, dwOldProtect, &dwBkup);

	return;
}

const char* print_in_format = "[IN] %.*s\n";

void __declspec(naked) in_packet_hook()
{
	__asm
	{
		PUSHAD
		MOV eax, [esi+4]
		ADD eax, 11
		PUSH eax
		MOV ecx, [esi+8]
		SUB ecx, 11
		PUSH ecx
		PUSH print_in_format
		CALL printf
		ADD esp, 12
		POPAD

		PUSH edi
		PUSH esi
		CALL DWORD PTR[eax + 16]
		JMP in_packet_hook_return
	}
}

void Patch(BYTE* pAddress, const unsigned char* data, const int dwLen)
{
	DWORD dwOldProtect, dwBkup;

	// give the paged memory read/write permissions

	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// overwrite the byte at pAddress with the patch data

	for (int i = 0; i < dwLen; i++)
		*(pAddress + i) = data[i];

	// restore the paged memory permissions saved in dwOldProtect

	VirtualProtect(pAddress, dwLen, dwOldProtect, &dwBkup);
}

void IdleLoop()
{
	while (true)
	{
		Sleep(100);
	}
}

void print_hex(const char* data, const int len)
{
	std::ostringstream ss;

	ss << std::hex << std::uppercase << std::setfill('0');
	for (int i = 0; i < len; i++) {
		ss << std::setw(2) << (int)data[i] << ' ';
	}

	const auto result = ss.str();
	std::cout << result << std::endl;
}

void __cdecl print_recv(char* msg, const int len) { printf("[RECV] %.*s\n", len, msg); /*print_hex(msg, len);*/ }
void __cdecl print_send(char* msg, const int len) { printf("[SEND] %.*s\n", len, msg); /*print_hex(msg, len);*/ }

void __cdecl print_import(const unsigned char* msg, const unsigned long len) { printBase64(msg, len); }

void __declspec(naked) decrypt_hook()
{
	__asm
	{
		CALL ctr_decrypt_rebase

		PUSHAD
		PUSH esi //edi
		PUSH ebx //ebp
		CALL print_recv
		ADD esp, 0x8
		POPAD

		JMP decrypt_hook_return_rebase
	}
}

void __declspec(naked) encrypt_hook()
{
	__asm
	{
		PUSHAD
		PUSH ebx
		PUSH ecx
		CALL print_send
		ADD esp, 0x8
		POPAD

		CALL ctr_encrypt_rebase

		JMP encrypt_hook_return_rebase
	}
}

void __declspec(naked) ecc_import_hook()
{
	__asm
	{
		PUSHAD
		PUSH edx
		PUSH ecx
		CALL print_import
		ADD esp, 0x8
		POPAD

		// restore old code
		MOV eax, ecx
		MOV[esp + 12], edx

		JMP ecc_import_hook_return_rebase
	}
}