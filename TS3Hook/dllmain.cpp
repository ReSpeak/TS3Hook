// dllmain.cpp : Defines the entry point for the DLL application.
#include "main.h"
#include <cstdio>
#include <Psapi.h>
#include "PatchTools.h"

#define REBASE(A) (A  + dwModuleBase)

BOOL APIENTRY DllMain(HMODULE hModule, const DWORD ul_reason_for_call, LPVOID lpReserved)
{
	DWORD dwModuleBase;
	DWORD modSize;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		const auto match = FindPattern(L"ts3client_win32.exe", MASK1, PATT1);
		if (match != NULL)
		{
			printf("Found packet dispatch: %X\n", match);
		}
		else
		{
			printf("Packet dispatcher not found, aborting");
			return FALSE;
		}

		in_packet_hook_return = match + OFFS1 + 5;
		MakeJMP((PBYTE)(match + OFFS1), in_packet_hook, 5);


		CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)IdleLoop, nullptr, NULL, nullptr);
		break;

		//case DLL_THREAD_ATTACH:
		//case DLL_THREAD_DETACH:
		//case DLL_PROCESS_DETACH:
		//	break;
	}
	return TRUE;
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

void IdleLoop()
{
	while (true)
	{
		Sleep(100);
	}
}