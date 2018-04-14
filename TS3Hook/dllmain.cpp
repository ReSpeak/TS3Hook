// dllmain.cpp : Defines the entry point for the DLL application.
#include "main.h"
#include "include/ts3_functions.h"
#include <cstdio>
#include "PatchTools.h"
#include <string>
#include <vector>
#include <sstream>
#include <iterator>
#include <fstream>
#include <algorithm>
#include <stdio.h>
#include <wincon.h>

#define PLUGINS_EXPORTDLL __declspec(dllexport)

// Plugin exports
extern "C" {
	PLUGINS_EXPORTDLL void ts3plugin_setFunctionPointers(const struct TS3Functions funcs);
	PLUGINS_EXPORTDLL void ts3plugin_onConnectStatusChangeEvent(uint64 serverConnectionHandlerID, int newStatus, unsigned int errorNumber);
}
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
std::string nickname;
bool nick_change_needed = false;
LPCWSTR lpFileName = L".\\HookConf.ini";
LPCWSTR lpSection = L"Config";
const char* prefix = "TS3Hook: ";
WCHAR outprefix[256];
WCHAR outsuffix[256];
WCHAR inprefix[256];
WCHAR insuffix[256];
std::vector<std::string> ignorecmds;
std::vector<std::string> blockcmds;
std::vector<std::string> clientver;
const std::string injectcmd(" msg=~cmd");
const std::string clientinit("clientinit ");
const std::string sendtextmessage("sendtextmessage ");
static struct TS3Functions ts3_functions;
anyID myID;
uint64 cid;


#define CONFSETT(var, form) if(GetLastError()) {\
		printf("%sFor "#var" using default: %"#form"\n", prefix, var);\
	} else {\
		printf("%sFor "#var" using: %"#form"\n", prefix, var);\
	}

std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}


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

bool file_exists(const LPCWSTR file_name)
{
	std::ifstream file(file_name);
	return file.good();
}
void ts3plugin_setFunctionPointers(const struct TS3Functions funcs) {
	ts3_functions = funcs;
}

void ts3plugin_onConnectStatusChangeEvent(uint64 serverConnectionHandlerID, int newStatus, unsigned int errorNumber) {
	if (newStatus == STATUS_CONNECTION_ESTABLISHED && nick_change_needed) {
		nick_change_needed = false;
		ts3_functions.getClientID(serverConnectionHandlerID, &myID);
		ts3_functions.getChannelOfClient(serverConnectionHandlerID, myID, &cid);
		std::string nick = "~cmdclientupdate~sclient_nickname=" + nickname;
		ts3_functions.requestSendChannelTextMsg(serverConnectionHandlerID, nick.c_str(), cid, NULL);
	}
}

void create_config(const LPCWSTR file_name)
{
	WritePrivateProfileString(lpSection, L"outprefix", L"[OUT]", file_name);
	WritePrivateProfileString(lpSection, L"outsuffix", L"", file_name);
	WritePrivateProfileString(lpSection, L"inprefix", L"[IN ]", file_name);
	WritePrivateProfileString(lpSection, L"insuffix", L"", file_name);
	WritePrivateProfileString(lpSection, L"ignorecmds", L"", file_name);
	WritePrivateProfileString(lpSection, L"blockcmds", L"", file_name);
	WritePrivateProfileString(lpSection, L"injectcmd", L" msg=~cmd", file_name);
	WritePrivateProfileString(lpSection, L"clientversion", L"", file_name);
	printf("%sCreated config %ls\n", prefix, file_name);
}

void replace_all(std::string& str, const std::string& from, const std::string& to) {
	if (from.empty() || str.empty())
		return;
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
	}
}

template<size_t Size>
void read_split_list(wchar_t(&splitbuffer)[Size], std::vector<std::string> &out)
{
	char outbuffer[Size];
	size_t converted;
	wcstombs_s<Size>(&converted, outbuffer, splitbuffer, Size);
	const std::string ignorestr(outbuffer, converted - 1);
	out = split(ignorestr, ',');
}

template<size_t Size>
void read_split_list_vertical(wchar_t(&splitbuffer)[Size], std::vector<std::string> &out)
{
	char outbuffer[Size];
	size_t converted;
	wcstombs_s<Size>(&converted, outbuffer, splitbuffer, Size);
	const std::string ignorestr(outbuffer, converted - 1);
	out = split(ignorestr, '|');
}

void read_config()
{
	if (!file_exists(lpFileName))
		create_config(lpFileName);

	GetPrivateProfileString(lpSection, L"outprefix", L"[OUT]", outprefix, sizeof(outprefix), lpFileName);
	//CONFSETT(outprefix, ls);
	GetPrivateProfileString(lpSection, L"outsuffix", L"", outsuffix, sizeof(outsuffix), lpFileName);
	//CONFSETT(outsuffix, ls);
	GetPrivateProfileString(lpSection, L"inprefix", L"[IN ]", inprefix, sizeof(inprefix), lpFileName);
	//CONFSETT(inprefix, ls);
	GetPrivateProfileString(lpSection, L"insuffix", L"", insuffix, sizeof(insuffix), lpFileName);
	//CONFSETT(insuffix, ls);
	wchar_t splitbuffer[4096];
	GetPrivateProfileString(lpSection, L"ignorecmds", L"", splitbuffer, sizeof(splitbuffer), lpFileName);
	read_split_list(splitbuffer, ignorecmds);
	printf("%sIgnoring ", prefix);
	for (const auto &igcmd : ignorecmds)
		printf("%s,", igcmd.c_str());
	printf("\n");
	GetPrivateProfileString(lpSection, L"blockcmds", L"", splitbuffer, sizeof(splitbuffer), lpFileName);
	if (hConsole != nullptr) SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	printf("%sBlocking ", prefix);
	read_split_list(splitbuffer, blockcmds);
	for (const auto &igcmd : blockcmds) {
		if (hConsole != nullptr) SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		printf("%s,", igcmd.c_str());
	}
	GetPrivateProfileString(lpSection, L"clientversion", L"", splitbuffer, sizeof(splitbuffer), lpFileName);
	read_split_list_vertical(splitbuffer, clientver);
	if (!clientver.empty()) {
		replace_all(clientver[0], " ", R"(\s)");
		replace_all(clientver[2], "/", R"(\/)");
	}
	printf("\n");
	//GetPrivateProfileString(lpSection, L"injectcmd", L" msg=~cmd", injectcmd, sizeof(injectcmd), lpFileName);
	//CONFSETT(injectcmd, ls);
}

bool core_hook()
{
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	if (hConsole != nullptr)
		SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	read_config();

	if (!try_hook())
	{
		if (hConsole != nullptr)
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
		printf("%sPacket dispatcher not found, aborting\n", prefix);
		return false;
	}

	if (hConsole != nullptr)
		SetConsoleTextAttribute(hConsole, 0);

	return true;
}

void STD_DECL log_in_packet(char* packet, int length)
{
	const auto buffer = std::string(packet, length);
	for each(std::string filter in ignorecmds) {
		if (!buffer.compare(0, filter.size(), filter))
			return;
	}
	if (hConsole != nullptr) SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	printf("%ls %.*s %ls\n", inprefix, length, packet, insuffix);
}

void STD_DECL log_out_packet(char* packet, int length)
{
	const auto buffer = std::string(packet, length);
	const auto find_pos_inject = buffer.find(injectcmd);
	const auto find_pos_cinit = buffer.find(clientinit);
	const auto find_pos_sendcmd = buffer.find(sendtextmessage);

	if (find_pos_inject != std::string::npos)
	{
		const int in_off = find_pos_inject + injectcmd.size();
		auto in_str = std::string(packet + in_off, length - in_off);

		replace_all(in_str, std::string("~s"), std::string(" "));

		memcpy(packet, in_str.c_str(), in_str.length());
		memset(packet + in_str.length(), ' ', length - in_str.length());

		if (hConsole != nullptr) SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	}
	else if (find_pos_cinit != std::string::npos && find_pos_sendcmd == std::string::npos && !clientver.empty())
	{
		const int client_ver = buffer.find("client_version=");
		const int client_platform = buffer.find("client_platform=");
		const int client_version_sign = buffer.find("client_version_sign=");
		const int client_key_offset = buffer.find("client_key_offset=");
		const int client_input_hardware = buffer.find("client_input_hardware=");
		const int client_nickname = buffer.find("client_nickname=");
		auto in_str = buffer;
		if (!clientver[2].empty()) {
			in_str.erase(client_version_sign + 20, client_key_offset - client_version_sign - 21);
			in_str.insert(client_version_sign + 20, clientver[2]);
		}
		if (!clientver[1].empty()) {
			in_str.erase(client_platform + 16, (client_input_hardware - client_platform - 17));
			in_str.insert(client_platform + 16, clientver[1]);
		}
		if (!clientver[0].empty()) {
			in_str.erase(client_ver + 15, (client_platform - client_ver - 16));
			in_str.insert(client_ver + 15, clientver[0]);
		}
		auto nickname_length = (client_ver - client_nickname - 17);
		
		int length_difference = buffer.size() - in_str.size();
		if (length_difference >= 0) {
			memcpy(packet, in_str.c_str(), in_str.length());
			memset(packet + in_str.length(), ' ', length - in_str.length());
		}
		else if (nickname_length > 3 && length_difference + nickname_length >= 0) {
			nickname = in_str.substr(client_nickname + 16, (client_ver - client_nickname - 17));
			replace_all(nickname, R"(\s)", " ");
			nick_change_needed = true;
			in_str.erase(client_nickname + 16, (client_ver - client_nickname - 17));
			in_str.insert(client_nickname + 16, random_string(3));
			memcpy(packet, in_str.c_str(), in_str.length());
			memset(packet + in_str.length(), ' ', length - in_str.length());
		}
		else {
			printf("[INFO] Couldn't set fake platform\n");
		}

		if (hConsole != nullptr) SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	}
	else
	{
		for each(std::string filter in ignorecmds) {
			if (!buffer.compare(0, filter.size(), filter))
				return;
		}
		for each(std::string filter in blockcmds) {
			if (!buffer.compare(0, filter.size(), filter)) {
				memset(packet, ' ', length);
				if (hConsole != nullptr) SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
				printf("%ls Blocking %s %ls\n", outprefix, filter.c_str(), outsuffix);
				return;
			}
		}

		if (hConsole != nullptr) SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	}
	printf("%ls %.*s %ls\n", outprefix, length, packet, outsuffix);
}

#ifdef ENV32
bool try_hook()
{
	const auto match_in_1 = FindPattern(MOD, PATT_IN_1, MASK_IN_1);

	const auto match_out_1 = FindPattern(MOD, PATT_OUT_1, MASK_OUT_1);

	if (match_in_1 != NULL && match_out_1 != NULL)
	{
		const SIZE_T OFFS_IN_1 = 13;
		packet_in_hook_return = match_in_1 + OFFS_IN_1 + 5;
		MakeJMP(reinterpret_cast<PBYTE>(match_in_1 + OFFS_IN_1), reinterpret_cast<PVOID>(packet_in_hook1), 5);

		const SIZE_T OFFS_OUT_1 = 33;
		packet_out_hook_return = match_out_1 + OFFS_OUT_1 + 8;
		MakeJMP(reinterpret_cast<PBYTE>(match_out_1 + OFFS_OUT_1), reinterpret_cast<PVOID>(packet_out_hook1), 8);
		if (hConsole != nullptr)
			SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		printf("%sHook successfull! (x86 PKGIN: %lX PKGOUT: %lX\n", prefix, match_in_1, match_out_1);
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
		if (hConsole != nullptr)
			SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	SIZE_T match_out = NULL;
	hookpt* pt_out = nullptr;
	for (hookpt &pt : OUT_HOOKS)
	{
		match_out = FindPattern(MOD, pt.PATT, pt.MASK);
		if (match_out != NULL) {
			if (hConsole != nullptr)
				SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
			pt_out = &pt;
			break;
		}
	}

	if (match_in_1 != NULL && match_out != NULL)
	{
		packet_in_hook_return = match_in_1 + 22;
		MakeJMP(reinterpret_cast<PBYTE>(match_in_1), packet_in_hook1, 22);

		packet_out_hook_return = match_out + pt_out->hook_return_offset;
		MakeJMP(reinterpret_cast<PBYTE>(match_out), pt_out->target_hook, pt_out->hook_length);
		if (hConsole != nullptr)
			SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		printf("%sHook successfull! (x64 PKGIN: %lX PKGOUT: %lX)\n", prefix, match_in_1, match_out);
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
