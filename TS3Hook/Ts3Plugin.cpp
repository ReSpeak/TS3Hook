#include "stdio.h"
#include "main.h"
#include "PatchTools.h"

#define PLUGIN_API_VERSION 22

const char* ts3plugin_name() { return "TS3Hook"; }
const char* ts3plugin_version() { return "1.2.2"; }

int ts3plugin_apiVersion() {
	int target = -1;
	SIZE_T match = NULL;

#ifdef ENV64
	if (match == NULL && (match = FindPattern(MOD, "\x89\x83\x00\x04\x00\x00\x83\xC0?\x83\xF8\x01\x0F\x87", "xxxxxxxx?xxxxx")))
		target = abs((int)(*(signed char*)(match + 8)));

	if (match == NULL && (match = FindPattern(MOD, "\x89\x83??\x00\x00\x83\xF8?\x0F\x84", "xx??xxxx?xx")))
		target = abs((int)(*(signed char*)(match + 8)));
#endif

	if (match == NULL)
	{
		printf("%s: Cannot auto-detect required PluginAPI version, using %d\n", ts3plugin_name(), PLUGIN_API_VERSION);
		return PLUGIN_API_VERSION;
	}

	printf("%s: Auto-detected required PluginAPI %d\n", ts3plugin_name(), target);
	return target;
}

const char* ts3plugin_author() { return "Splamy, Bluscream, alex720, exp111, Nicer"; }
const char* ts3plugin_description() { return "Prints command packets on the console.\n\nhttps://github.com/ReSpeak/TS3Hook"; }

int ts3plugin_init() {
	printf("-= %s v%s by %s =-\n", ts3plugin_name(), ts3plugin_version(), ts3plugin_author());
	return core_hook() ? 0 : 1;
}
void ts3plugin_shutdown() {
	printf("%s: Shutting down\n", ts3plugin_name());
}