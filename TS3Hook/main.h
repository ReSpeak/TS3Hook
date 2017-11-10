// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#ifndef MAIN_H
#define MAIN_H

#include <windows.h>
#include <Psapi.h>

// CONFIG
const DWORD call_to_ctr_decrypt = 0x006A49E9; //0x00595D69;
const DWORD call_to_ctr_encrypt = 0x006A4C4A; //0x005957EB;
const DWORD ctr_decrypt = 0x006A2F90; //0x00594790;
const DWORD ctr_encrypt = 0x00513CA0; //0x004C2210;
//const DWORD ecc_import = 0x00591EE0;
//const DWORD skip_compress_patch = 0x00576C01;

// AUTO CALCED
const DWORD decrypt_hook_return = call_to_ctr_decrypt + 0x5;
const DWORD encrypt_hook_return = call_to_ctr_encrypt + 0x5;
//const DWORD ecc_hook_return = ecc_import + 0x6;

// RUNTIME CALCED
DWORD ctr_decrypt_rebase = 0x0;
DWORD ctr_encrypt_rebase = 0x0;
DWORD decrypt_hook_return_rebase = 0x0;
DWORD encrypt_hook_return_rebase = 0x0;
DWORD ecc_import_hook_return_rebase = 0x0;

DWORD in_packet_hook_return = 0x0;

// FUNCTION DECLS
void MakeJMP(BYTE* pAddress, void* dwJumpTo, DWORD dwLen);
void Patch(BYTE* pAddress, const unsigned char* data, int dwLen);
void IdleLoop();
void decrypt_hook();
void encrypt_hook();
void ecc_import_hook();

void in_packet_hook();

MODULEINFO GetModuleInfo(const LPCWSTR szModule);
DWORD FindPattern(const LPCWSTR module, char *pattern, char *mask);
DWORD GetModuleSize(LPCWSTR szModule);
#endif
