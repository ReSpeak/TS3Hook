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

#ifdef ENV32
void packet_in_hook1();
void packet_out_hook1();
#else
extern "C"
{
	void packet_in_hook1();
}
#endif

#endif // MAIN_H
