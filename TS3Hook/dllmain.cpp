// dllmain.cpp : Defines the entry point for the DLL application.
#include "main.h"
#include <cstdio>
#include <Psapi.h>
#include "PatchTools.h"

BOOL APIENTRY DllMain(HMODULE hModule, const DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		printf("-==== TS3HOOK 1.0 ====-\n");
		printf("-= Written by Splamy =-\n");

		const auto match_in_1 = FindPattern(L"ts3client_win32.exe", MASK_IN_1, PATT_IN_1);
		if (match_in_1 != NULL)
			printf("> Found PKGIN1: %X\n", match_in_1);

		const auto match_out_1 = FindPattern(L"ts3client_win32.exe", MASK_OUT_1, PATT_OUT_1);
		if (match_out_1 != NULL)
			printf("> Found PKGOUT1: %X\n", match_out_1);

		if (match_in_1 != NULL && match_out_1 != NULL)
		{
			const DWORD OFFS_IN_1 = 13;
			packet_in_hook_return = match_in_1 + OFFS_IN_1 + 5;
			MakeJMP((PBYTE)(match_in_1 + OFFS_IN_1), packet_in_hook1, 5);

			const DWORD OFFS_OUT_1 = 33;
			packet_out_hook_return = match_out_1 + OFFS_OUT_1 + 8;
			MakeJMP((PBYTE)(match_out_1 + OFFS_OUT_1), packet_out_hook1, 8);
		}
		else
		{
			printf("Packet dispatcher not found, aborting");
			return FALSE;
		}

		CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)idle_loop, nullptr, NULL, nullptr);
		break;

		//case DLL_THREAD_ATTACH:
		//case DLL_THREAD_DETACH:
		//case DLL_PROCESS_DETACH:
		//	break;
	}
	return TRUE;
}

const char* print_in_format1 = "[IN] %.*s\n";
void __declspec(naked) packet_in_hook1()
{
	__asm
	{
		// +11

		PUSHAD
		MOV eax, [esi + 4]
		ADD eax, 11
		PUSH eax // str
		MOV ecx, [esi + 8]
		SUB ecx, 11
		PUSH ecx // len
		PUSH print_in_format1
		CALL printf
		ADD esp, 12
		POPAD

		// overwritten
		PUSH edi
		PUSH esi
		CALL DWORD PTR[eax + 16]
		JMP packet_in_hook_return
	}
}

const char* print_out_format1 = "[OT] %.*s\n";
void __declspec(naked) packet_out_hook1()
{
	__asm
	{
		// +13

		PUSHAD
		MOV eax, [edi]
		ADD eax, 13
		PUSH eax // str
		MOV ecx, [edi + 4]
		SUB ecx, 13
		PUSH ecx // len
		PUSH print_out_format1
		CALL printf
		ADD esp, 12
		POPAD

		// overwritten
		CMP DWORD PTR[ebp + 16], 1
		SETZ BYTE PTR [ebp+4]
		JMP packet_out_hook_return
	}
}

void idle_loop()
{
	while (true)
	{
		Sleep(100);
	}
}