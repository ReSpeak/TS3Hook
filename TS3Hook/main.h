// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#ifndef MAIN_H
#define MAIN_H

#include <windows.h>

// CONFIG
const char* MASK_IN_1 = "\x8B\x4F\x3C\x6A\x00\xFF\x77\x44\xFF\x77\x40\x8B\x01\x57\x56\xFF\x50\x10";
const char* PATT_IN_1 = "xxxxxxxxxxxxxxxxxx";

const char* MASK_OUT_1 = "\xC6\x45\xFC\x06\x80\xF9\x02\x74\x09\x80\xF9\x03";
const char* PATT_OUT_1 = "xxxxxxxxxxxx";

// RUNTIME CALCED
DWORD packet_in_hook_return = 0x0;
DWORD packet_out_hook_return = 0x0;

// FUNCTION DECLS
void idle_loop();

void packet_in_hook1();
void packet_out_hook1();
#endif
