// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#ifndef MAIN_H
#define MAIN_H

#include <windows.h>

// CONFIG
const char* MASK1 = "\x8B\x4F\x3C\x6A\x00\xFF\x77\x44\xFF\x77\x40\x8B\x01\x57\x56\xFF\x50\x10";
const char* PATT1 = "xxxxxxxxxxxxxxxxxx";
const DWORD OFFS1 = 13;

// RUNTIME CALCED
DWORD in_packet_hook_return = 0x0;

// FUNCTION DECLS
void IdleLoop();

void in_packet_hook();
#endif
