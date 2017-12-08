// dllmain.cpp : Defines the entry point for the DLL application.
#include "main.h"
#include <cstdio>
#include "PatchTools.h"
#include <string>
#include <vector>
#include <sstream>
#include <iterator>

#ifdef ENV32
#define STD_DECL __cdecl

// Ver: 3.1.6>3.1.4.2>3.0.17  !3.0.16
const char* PATT_IN_1 = "\x8B\x4F\x3C\x6A\x00\xFF\x77\x44\xFF\x77\x40\x8B\x01\x57\x56\xFF\x50\x10";
const char* MASK_IN_1 = "xxxxxxxxxxxxxxxxxx";

// Ver: 3.1.6>3.1.4.2>3.1>?  !3.0.17
const char* PATT_OUT_1 = "\xC6\x45\xFC\x06\x80\xF9\x02\x74\x09\x80\xF9\x03";
const char* MASK_OUT_1 = "xxxxxxxxxxxx";
#else
#define STD_DECL

const char* PATT_IN_1 = "\x49\x8B\x4E\x50\x48\x8B\x01\xC6\x44\x24\x20\x00\x4D\x8B\x4E\x58\x4D\x8B\xC6\x48\x8B\xD3\xFF\x50\x20\xEB";
const char* MASK_IN_1 = "xxxxxxxxxxxxxxxxxxxxxxxxxx";

hookpt OUT_HOOKS[] = {
	// "xx?xxxxxxxxx?xxxxx"
	hookpt{ 18, 18, packet_out_hook1, "\x89\x45\x00\x83\xF8\x01\x0F\x94\xC1\x88\x4C\x24\x44\x80\x7C\x24\x40\x00" ,"xxxxxxxxxxxxxxxxxx" },
	hookpt{ 18, 18, packet_out_hook2, "\x89\x45\xE0\x83\xF8\x01\x0F\x94\xC1\x88\x4C\x24\x50\x80\x7C\x24\x40\x00" ,"xxxxxxxxxxxxxxxxxx" },
	hookpt{ 17, 17, packet_out_hook3, "\x48\x8B\x10\x48\x89\x54\x24\x50\x48\x89\x54\x24\x78\x48\x8B\x58\x08", "xxxxxxxxxxxxxxxxx" }
};
#endif

HANDLE hConsole = nullptr;

std::vector<std::string> inFilter = {
	//examples
	//std::string("notifyclientupdated"),
	//std::string("notifyclientleftview")
};
std::vector<std::string> outFilter = {
	//examples
	//std::string("channelsubscribe"),
};

// RUNTIME CALCED
extern "C"
{
	SIZE_T packet_in_hook_return = 0x0;
	SIZE_T packet_out_hook_return = 0x0;
}

LPCWSTR lpFileName = L".\\HookConf.ini";
LPCWSTR lpSection = L"Config";
WCHAR outprefix[256];
WCHAR inprefix[256];
std::vector<std::string> ignorecmds;

#define CONFSETT(var, form) if(GetLastError()) { printf("For "#var" using default: %"#form"\n", var); } else { printf("For "#var" using: %"#form"\n", var); }

template<typename Out>
void split(const std::string &s, const char delim, Out result) {
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		*(result++) = item;
	}
}

std::vector<std::string> split(const std::string &s, const char delim) {
	std::vector<std::string> elems;
	split(s, delim, std::back_inserter(elems));
	return elems;
}

void read_config()
{
	GetPrivateProfileString(lpSection, L"outprefix", L"[OUT]", outprefix, sizeof(outprefix), lpFileName);
	CONFSETT(outprefix, ls);
	GetPrivateProfileString(lpSection, L"inprefix", L"[IN ]", inprefix, sizeof(inprefix), lpFileName);
	CONFSETT(inprefix, ls);
	WCHAR ignorecmds_wc[4096];
	GetPrivateProfileString(lpSection, L"ignorecmds", L"", ignorecmds_wc, sizeof(ignorecmds_wc), lpFileName);
	CHAR ignorecmds_c[sizeof(ignorecmds_wc)];
	wcstombs(ignorecmds_c, ignorecmds_wc, sizeof(ignorecmds_wc));
	const std::string ignorestr(ignorecmds_c);
	ignorecmds = split(ignorestr, ',');
	for(auto igcmd : ignorecmds)
	{
		printf("Ignoring %s\n", igcmd.c_str());
	}
}

bool core_hook()
{
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	if (hConsole != nullptr)
		SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	printf("-==== TS3HOOK 1.0 ====-\n");
	printf("-= Written by Splamy =-\n");

	read_config();

	if (!try_hook())
	{
		if (hConsole != nullptr)
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
		printf("Packet dispatcher not found, aborting\n");
		return false;
	}
	else
	{
		if (hConsole != nullptr)
			SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		printf("Hook successful!\n");
	}

	if (hConsole != nullptr)
		SetConsoleTextAttribute(hConsole, 0);

	return true;
}

void STD_DECL log_in_packet(char* packet, int length)
{
	std::string buffer = std::string(packet);
	for each(std::string filter in ignorecmds) {
		if (!buffer.compare(0, filter.size(), filter))
			return;
	}
	if (hConsole != nullptr)
		SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	printf("[ IN] %.*s\n", length, packet);
}

void STD_DECL log_out_packet(char* packet, int length)
{
	std::string buffer = std::string(packet);
	for each(std::string filter in ignorecmds) {
		if (!buffer.compare(0, filter.size(), filter))
			return;
	}
	if (hConsole != nullptr)
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	printf("%ls %.*s\n", outprefix, length, packet);
}

#ifdef ENV32
bool try_hook()
{
	const auto match_in_1 = FindPattern(MOD, PATT_IN_1, MASK_IN_1);
	if (match_in_1 != NULL)
		printf("> Found PKGIN1: %zX\n", match_in_1);

	const auto match_out_1 = FindPattern(MOD, PATT_OUT_1, MASK_OUT_1);
	if (match_out_1 != NULL)
		printf("> Found PKGOUT1: %zX\n", match_out_1);

	if (match_in_1 != NULL && match_out_1 != NULL)
	{
		const SIZE_T OFFS_IN_1 = 13;
		packet_in_hook_return = match_in_1 + OFFS_IN_1 + 5;
		MakeJMP((PBYTE)(match_in_1 + OFFS_IN_1), packet_in_hook1, 5);

		const SIZE_T OFFS_OUT_1 = 33;
		packet_out_hook_return = match_out_1 + OFFS_OUT_1 + 8;
		MakeJMP((PBYTE)(match_out_1 + OFFS_OUT_1), packet_out_hook1, 8);
		return true;
	}

	return false;
}

void __declspec(naked) packet_in_hook1()
{
	__asm
	{
		// +11

		PUSHAD
		MOV ecx, [esi + 8]
		SUB ecx, 11
		PUSH ecx // len
		MOV eax, [esi + 4]
		ADD eax, 11
		PUSH eax // str
		CALL log_in_packet
		ADD esp, 8
		POPAD

		// overwritten
		PUSH edi
		PUSH esi
		CALL DWORD PTR[eax + 16]
		JMP packet_in_hook_return
	}
}

void __declspec(naked) packet_out_hook1()
{
	__asm
	{
		// +13

		PUSHAD
		MOV ecx, [edi + 4]
		SUB ecx, 13
		PUSH ecx // len
		MOV eax, [edi]
		ADD eax, 13
		PUSH eax // str
		CALL log_out_packet
		ADD esp, 8
		POPAD

		// overwritten
		CMP DWORD PTR[ebp + 16], 1
		SETZ BYTE PTR[ebp + 4]
		JMP packet_out_hook_return
	}
}
#else
bool try_hook()
{
	const auto match_in_1 = FindPattern(MOD, PATT_IN_1, MASK_IN_1);
	if (match_in_1 != NULL)
		printf("> Found PKGIN: %zX\n", match_in_1);

	SIZE_T match_out = NULL;
	hookpt* pt_out = nullptr;
	for (hookpt &pt : OUT_HOOKS)
	{
		match_out = FindPattern(MOD, pt.PATT, pt.MASK);
		if (match_out != NULL) {
			pt_out = &pt;
			printf("> Found PKGOUT: %zX\n", match_out);
			break;
		}
	}

	if (match_in_1 != NULL && match_out != NULL)
	{
		packet_in_hook_return = match_in_1 + 22;
		MakeJMP((PBYTE)(match_in_1), packet_in_hook1, 22);

		packet_out_hook_return = match_out + pt_out->hook_return_offset;
		MakeJMP((PBYTE)(match_out), pt_out->target_hook, pt_out->hook_length);
		return true;
	}

	return false;
}
#endif

void idle_loop()
{
	while (true)
	{
		Sleep(100);
	}
}
