#pragma once

#include <windows.h>

DWORD FindPattern(const LPCWSTR module, const char *pattern, const char *mask);
void MakeJMP(BYTE* pAddress, void* dwJumpTo, DWORD dwLen);