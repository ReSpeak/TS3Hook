// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#ifndef MAIN_H
#define MAIN_H
#include <windows.h>

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
bool TryHook();
void idle_loop();

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

#endif // MAIN_H
