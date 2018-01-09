// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#ifndef MAIN_H
#define MAIN_H
#include <Windows.h>

#if _WIN32 || _WIN64
#if _WIN64
#define ENV64
#else
#define ENV32
#endif
#endif

// Check GCC
#if __GNUC__
#if __x86_64__ || __ppc64__
#define ENV64
#else
#define ENV32
#endif
#endif

// FUNCTION DECLS
bool core_hook();
bool try_hook();
void idle_loop();
void read_config();

#ifdef ENV32
#define MOD (L"ts3client_win32.exe")
#else
#define MOD (L"ts3client_win64.exe")
#endif

extern "C"
{
	void log_in_packet(char* packet, int length);
	void log_out_packet(char* packet, int length);

	void packet_in_hook1();
	void packet_out_hook1();
#ifdef ENV64
	void packet_out_hook2();
	void packet_out_hook3();
#endif
}

const struct hookpt
{
	const SIZE_T hook_return_offset;
	const SIZE_T hook_length;
	void (*target_hook)();
	const char* PATT;
	const char* MASK;
};

#define PLUGINS_EXPORTDLL __declspec(dllexport)

// Plugin exports
extern "C" {
	/* Required functions */
	PLUGINS_EXPORTDLL const char* ts3plugin_name();
	PLUGINS_EXPORTDLL const char* ts3plugin_version();
	PLUGINS_EXPORTDLL int ts3plugin_apiVersion();
	PLUGINS_EXPORTDLL const char* ts3plugin_author();
	PLUGINS_EXPORTDLL const char* ts3plugin_description();
	PLUGINS_EXPORTDLL void ts3plugin_setFunctionPointers(void* funcs);
	PLUGINS_EXPORTDLL int ts3plugin_init();
	PLUGINS_EXPORTDLL void ts3plugin_shutdown();
}

#endif // MAIN_H
