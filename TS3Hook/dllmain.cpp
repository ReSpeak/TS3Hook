﻿// dllmain.cpp : Defines the entry point for the DLL application.
#include "main.h"
#include "util.h"
#include <cstdio>
#include "PatchTools.h"
#include <string>
#include <vector>
#include <sstream>
#include <iterator>
#include <fstream>

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
hookpt IN_HOOKS[] = {
	hookpt{ 22, 22, packet_in_hook1, "\x49\x8B\x4E\x50\x48\x8B\x01\xC6\x44\x24\x20\x00\x4D\x8B\x4E\x58\x4D\x8B\xC6\x48\x8B\xD3\xFF\x50\x20\xEB", "xxxxxxxxxxxxxxxxxxxxxxxxxx" },
	hookpt{ 22, 22, packet_in_hook2, "\x49\x8B\x4F\x50\x48\x8B\x01\xC6\x44\x24\x20\x00\x4D\x8B\x4F\x58\x4D\x8B\xC7\x48\x8B\xD3\xFF\x50\x20\x41", "xxxxxxxxxxxxxxxxxxxxxxxxxx" },
};

hookpt OUT_HOOKS[] = {
	hookpt{ 18, 18, packet_out_hook1, "\x89\x45\x00\x83\xF8\x01\x0F\x94\xC1\x88\x4C\x24\x44\x80\x7C\x24\x40\x00", "xxxxxxxxxxxxxxxxxx" },
	hookpt{ 18, 18, packet_out_hook2, "\x89\x45\xE0\x83\xF8\x01\x0F\x94\xC1\x88\x4C\x24\x50\x80\x7C\x24\x40\x00", "xxxxxxxxxxxxxxxxxx" },
	hookpt{ 17, 17, packet_out_hook3, "\x48\x8B\x10\x48\x89\x54\x24\x50\x48\x89\x54\x24\x78\x48\x8B\x58\x08", "xxxxxxxxxxxxxxxxx" },
	hookpt{ 18, 18, packet_out_hook4, "\x89\x85\xE0\x09\x00\x00\x41\x3B\xC6\x41\x0F\x94\xC4\x80\x7C\x24\x40\x00", "xxxxxxxxxxxxxxxxxx" },
};
#endif

#define sizeofa(a) (sizeof(a) / sizeof(a[0]))

#define CRED (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define CGREEN (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define CBLUE (FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define CYELLOW (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define CCYAN (FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define CPINK (FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY)

#define CWRITE(color, format, ...) {\
		if (hConsole != nullptr) SetConsoleTextAttribute(hConsole, color);\
		printf (format, __VA_ARGS__);\
		if (hConsole != nullptr) SetConsoleTextAttribute(hConsole, 15);\
	}

HANDLE hConsole = nullptr;

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
wchar_t outprefix[256];
wchar_t outsuffix[256];
wchar_t inprefix[256];
wchar_t insuffix[256];
wchar_t bypass_modalquit[3];
wchar_t teaspeak_anti_error[3];
std::vector<std::string> ignorecmds;
std::vector<std::string> blockcmds;
std::vector<std::string> clientver;
const std::string injectcmd(" msg=~cmd");
const std::string outjectcmd(" msg=-cmd");
const std::string clientinit("clientinit ");
const std::string sendtextmessage("sendtextmessage ");
const std::string notifytextmessage("notifytextmessage ");
const std::string hostmsg_mode("virtualserver_hostmessage_mode=3");
const std::string not_implemented("error id=2 msg=not\\simplemented");
const std::string bell = std::string(1, '\a');
const std::string null_str = std::string(1, '\0');
static struct TS3Functions ts3_functions;
anyID myID;
uint64 cid;

#define CONFSETT(var, form) if(GetLastError()) {\
		printf("%sFor "#var" using default: %"#form"\n", prefix, var);\
	} else {\
		printf("%sFor "#var" using: %"#form"\n", prefix, var);\
	}

template<typename Out>
void split(const std::string& s, const char delim, Out result) {
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		*(result++) = item;
	}
}

std::vector<std::string> split(const std::string& s, const char delim) {
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

int ts3plugin_onServerErrorEvent(uint64 serverConnectionHandlerID, const char* errorMessage, unsigned int error, const char* returnCode, const char* extraMessage)
{
	if (strcmp(returnCode, "th") == 0)
		return 1;
	return 0;
}

void create_config(const LPCWSTR file_name)
{
	WritePrivateProfileString(lpSection, L"outprefix", L"[OUT]", file_name);
	WritePrivateProfileString(lpSection, L"outsuffix", L"", file_name);
	WritePrivateProfileString(lpSection, L"inprefix", L"[IN ]", file_name);
	WritePrivateProfileString(lpSection, L"insuffix", L"", file_name);
	WritePrivateProfileString(lpSection, L"ignorecmds", L"", file_name);
	WritePrivateProfileString(lpSection, L"blockcmds", L"connectioninfoautoupdate,setconnectioninfo,clientchatcomposing", file_name);
	WritePrivateProfileString(lpSection, L"clientversion", L"3.?.? [Build: 5680278000]|Windows|DX5NIYLvfJEUjuIbCidnoeozxIDRRkpq3I9vVMBmE9L2qnekOoBzSenkzsg2lC9CMv8K5hkEzhr2TYUYSwUXCg==", file_name);
	WritePrivateProfileString(lpSection, L"bypass_modalquit", L"1", file_name);
	WritePrivateProfileString(lpSection, L"teaspeak_anti_error", L"1", file_name);
	WritePrivateProfileString(lpSection, L"useunicode", L"1", file_name);
	//printf("%sCreated config %ls\n", prefix, file_name);
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
void read_split_list(wchar_t(&splitbuffer)[Size], std::vector<std::string>& out, char split_char)
{
	char outbuffer[Size];
	size_t converted;
	wcstombs_s<Size>(&converted, outbuffer, splitbuffer, Size);
	const std::string ignorestr(outbuffer, converted - 1);
	out = split(ignorestr, split_char);
}

void read_config()
{
	if (!file_exists(lpFileName)) {
		CWRITE(CYELLOW, "Make sure to start your Teamspeak Client as admin atleast once to create \"HookConf.ini\"!\n");
		create_config(lpFileName);
	}
	GetPrivateProfileString(lpSection, L"outprefix", L"[OUT]", outprefix, sizeofa(outprefix), lpFileName);
	//CONFSETT(outprefix, ls);
	GetPrivateProfileString(lpSection, L"outsuffix", L"", outsuffix, sizeofa(outsuffix), lpFileName);
	//CONFSETT(outsuffix, ls);
	GetPrivateProfileString(lpSection, L"inprefix", L"[IN ]", inprefix, sizeofa(inprefix), lpFileName);
	//CONFSETT(inprefix, ls);
	GetPrivateProfileString(lpSection, L"insuffix", L"", insuffix, sizeofa(insuffix), lpFileName);
	//CONFSETT(insuffix, ls);
	wchar_t splitbuffer[4096];
	GetPrivateProfileString(lpSection, L"ignorecmds", L"", splitbuffer, sizeofa(splitbuffer), lpFileName);
	read_split_list(splitbuffer, ignorecmds, ',');
	CWRITE(CCYAN, "%sIgnoring ", prefix);
	for (const auto& cmd : ignorecmds)
		CWRITE(CCYAN, "%s,", cmd.c_str());
	printf("\n");
	GetPrivateProfileString(lpSection, L"blockcmds", L"", splitbuffer, sizeofa(splitbuffer), lpFileName);
	CWRITE(CYELLOW, "%sBlocking ", prefix);
	read_split_list(splitbuffer, blockcmds, ',');
	for (const auto& cmd : blockcmds)
		CWRITE(CYELLOW, "%s,", cmd.c_str());
	printf("\n");
	GetPrivateProfileString(lpSection, L"clientversion", L"", splitbuffer, sizeofa(splitbuffer), lpFileName);
	read_split_list(splitbuffer, clientver, '|');
	for (auto& versionpart : clientver)
	{
		replace_all(versionpart, " ", R"(\s)");
		replace_all(versionpart, "/", R"(\/)");
	}
	GetPrivateProfileString(lpSection, L"bypass_modalquit", L"1", bypass_modalquit, sizeofa(bypass_modalquit), lpFileName);
	GetPrivateProfileString(lpSection, L"teaspeak_anti_error", L"1", teaspeak_anti_error, sizeofa(teaspeak_anti_error), lpFileName);
	wchar_t useunicode[1];
	GetPrivateProfileString(lpSection, L"useunicode", L"1", useunicode, sizeofa(useunicode), lpFileName);
	if (wcscmp(useunicode, L"1") == 0) {
		SetConsoleOutputCP(65001);
		CWRITE(CCYAN, "Using UTF-8 encoding");
		printf("\n");
	}
}

bool core_hook()
{
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	read_config();

	if (!try_hook())
	{
		CWRITE(CRED, "%sPacket dispatcher not found, aborting\n", prefix);
		return false;
	}

	return true;
}

void STD_DECL log_in_packet(char* packet, int length)
{
	auto buffer = std::string(packet, length);
	replace_all(buffer, bell, "");
	memcpy(packet, buffer.c_str(), buffer.length());
	memset(packet + buffer.length(), ' ', length - buffer.length());
	const auto find_pos_inits = buffer.find("initserver ");
	const auto find_pos_err = buffer.find(not_implemented);
	const auto find_pos_outject = buffer.find(outjectcmd);
	const auto find_pos_notcmd = buffer.find(notifytextmessage);
	bool modified = false;

	if (find_pos_outject != std::string::npos)
	{
		const auto in_off = find_pos_outject + outjectcmd.size();
		auto in_str = std::string(packet + in_off, length - in_off);
		replace_all(in_str, std::string("~s"), std::string(" "));
		replace_all(in_str, std::string("\\\\s"), std::string("\\s"));
		memcpy(packet, in_str.c_str(), in_str.length());
		memset(packet + in_str.length(), ' ', length - in_str.length());
		modified = true;
	}
	else if (find_pos_inits != std::string::npos) {
		const auto virtualserver_hostmessage_mode = buffer.find(hostmsg_mode);
		const auto virtualserver_hostmessage_set = buffer.find("virtualserver_hostmessage=");
		if (virtualserver_hostmessage_mode != std::string::npos && virtualserver_hostmessage_set != std::string::npos && wcscmp(L"1", bypass_modalquit) == 0) {
			auto in_str = buffer;
			replace_all(in_str, hostmsg_mode, "virtualserver_hostmessage_mode=2");
			memcpy(packet, in_str.c_str(), in_str.length());
			memset(packet + in_str.length(), ' ', length - in_str.length());
			ts3_functions.printMessageToCurrentTab("TS3Hook: The server you're connecting to has it's hostmessage mode set to [color=red]MODALQUIT[/color], but you can stay connected ;)");
			modified = true;
		}
	}
	else if (find_pos_err != std::string::npos && wcscmp(L"1", teaspeak_anti_error) == 0) {
		auto in_str = buffer;
		replace_all(in_str, not_implemented, "error id=0 msg return_code=th");
		memcpy(packet, in_str.c_str(), in_str.length());
		memset(packet + in_str.length(), ' ', length - in_str.length());
		modified = true;
	}
	for each (std::string filter in ignorecmds) {
		if (!buffer.compare(0, filter.size(), filter))
			return;
	}
	CWRITE(modified ? CPINK : CCYAN, "%ls %.*s %ls\n", inprefix, length, packet, insuffix);
}

void STD_DECL log_out_packet(char* packet, int length)
{
	auto buffer = std::string(packet, length);
	replace_all(buffer, "\a", "_");
	replace_all(buffer, null_str, "_");
	memcpy(packet, buffer.c_str(), buffer.length());
	memset(packet + buffer.length(), ' ', length - buffer.length());
	const auto find_pos_inject = buffer.find(injectcmd);
	const auto find_pos_cinit = buffer.find(clientinit);
	const auto find_pos_sendcmd = buffer.find(sendtextmessage);
	bool injected = false;

	if (find_pos_inject != std::string::npos)
	{
		const auto in_off = find_pos_inject + injectcmd.size();
		auto in_str = std::string(packet + in_off, length - in_off);

		replace_all(in_str, std::string("~s"), std::string(" "));

		memcpy(packet, in_str.c_str(), in_str.length());
		memset(packet + in_str.length(), ' ', length - in_str.length());

		injected = true;
	}
	else if (find_pos_cinit != std::string::npos && find_pos_sendcmd == std::string::npos && !clientver.empty())
	{
		const auto client_ver = find_param(buffer, "client_version=");
		const auto client_platform = find_param(buffer, "client_platform=");
		const auto client_version_sign = find_param(buffer, "client_version_sign=");
		const auto client_nickname = find_param(buffer, "client_nickname=");
		auto in_str = buffer;
		if (!clientver[2].empty()) {
			in_str.erase(std::get<0>(client_version_sign), std::get<1>(client_version_sign));
			in_str.insert(std::get<0>(client_version_sign), clientver[2]);
		}
		if (!clientver[1].empty()) {
			in_str.erase(std::get<0>(client_platform), std::get<1>(client_platform));
			in_str.insert(std::get<0>(client_platform), clientver[1]);
		}
		if (!clientver[0].empty()) {
			in_str.erase(std::get<0>(client_ver), std::get<1>(client_ver));
			in_str.insert(std::get<0>(client_ver), clientver[0]);
		}

		const auto length_difference = (long)buffer.size() - (long)in_str.size();
		if (length_difference >= 0) {
			memcpy(packet, in_str.c_str(), in_str.length());
			memset(packet + in_str.length(), ' ', length - in_str.length());
		}
		else if (length_difference + (long)std::get<1>(client_nickname) - 3 >= 0) {
			nickname = in_str.substr(std::get<0>(client_nickname), std::get<1>(client_nickname));
			replace_all(nickname, R"(\s)", " ");
			nick_change_needed = true;
			in_str.erase(std::get<0>(client_nickname), std::get<1>(client_nickname));
			in_str.insert(std::get<0>(client_nickname), random_string(3));
			memcpy(packet, in_str.c_str(), in_str.length());
			memset(packet + in_str.length(), ' ', length - in_str.length());
		}
		else {
			printf("[INFO] Couldn't set fake platform. Choose a longer nickname.\n");
		}

		injected = true;
	}
	else
	{
		for each (std::string filter in ignorecmds) {
			if (!buffer.compare(0, filter.size(), filter))
				return;
		}
		for each (std::string filter in blockcmds) {
			if (!buffer.compare(0, filter.size(), filter)) {
				memset(packet, ' ', length);
				CWRITE(CYELLOW, "%ls Blocking %s %ls\n", outprefix, filter.c_str(), outsuffix);
				return;
			}
		}
	}

	CWRITE(injected ? CPINK : CGREEN, "%ls %.*s %ls\n", outprefix, length, packet, outsuffix);
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

		CWRITE(CGREEN, "%sHook successfull! (x86 PKGIN: %zX PKGOUT: %zX\n", prefix, match_in_1, match_out_1);
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
	SIZE_T match_in = NULL;
	hookpt* pt_in = nullptr;
	for (hookpt& pt : IN_HOOKS)
	{
		match_in = FindPattern(MOD, pt.PATT, pt.MASK);
		if (match_in != NULL)
		{
			pt_in = &pt;
			break;
		}
	}

	SIZE_T match_out = NULL;
	hookpt* pt_out = nullptr;
	for (hookpt& pt : OUT_HOOKS)
	{
		match_out = FindPattern(MOD, pt.PATT, pt.MASK);
		if (match_out != NULL)
		{
			pt_out = &pt;
			break;
		}
	}

	if (match_in != NULL && match_out != NULL)
	{
		packet_in_hook_return = match_in + pt_in->hook_return_offset;
		MakeJMP(reinterpret_cast<PBYTE>(match_in), pt_in->target_hook, pt_in->hook_length);

		packet_out_hook_return = match_out + pt_out->hook_return_offset;
		MakeJMP(reinterpret_cast<PBYTE>(match_out), pt_out->target_hook, pt_out->hook_length);
		CWRITE(CGREEN, "%sHook successfull! (x64 PKGIN: %zX PKGOUT: %zX)\n", prefix, match_in, match_out);
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
