#include "stdio.h"
#include "main.h"
#include "PatchTools.h"

const char* ts3plugin_name() { return "TS3Hook"; }
const char* ts3plugin_version() { return "1.0"; }

int ts3plugin_apiVersion() {
	int target = -1;
	SIZE_T match = NULL;

	if (match == NULL && (match = FindPattern(MOD, "\x89\x83\x00\x04\x00\x00\x83\xC0?\x83\xF8\x01\x0F\x87", "xxxxxxxx?xxxxx")))
		target = abs((int)(*(signed char*)(match + 8)));

	if (match == NULL && (match = FindPattern(MOD, "\x89\x83??\x00\x00\x83\xF8?\x0F\x84", "xx??xxxx?xx")))
		target = abs((int)(*(signed char*)(match + 8)));

	if (match == NULL)
	{
		printf("Cannot auto-dedect version\n");
		return 22;
	}

	printf("Client expects %d\n", target);
	return target;
}

const char* ts3plugin_author() { return "Splamy"; }
const char* ts3plugin_description() { return "Prints command packets on the console."; }
void ts3plugin_setFunctionPointers(void* funcs) { }

int ts3plugin_init() { return CoreHook() ? 0 : 1; }
void ts3plugin_shutdown() {
	printf("shutdown tshook");
}