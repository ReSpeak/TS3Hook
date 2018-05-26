#pragma once

#include <windows.h>

SIZE_T FindPattern(const LPCWSTR module, const char *pattern, const char *mask);
void MakeJMP(const PBYTE pAddress, const PVOID dwJumpTo, const SIZE_T dwLen);
void PatchBytes(const PBYTE pAddress, const BYTE overwrite[], const SIZE_T dwLen);