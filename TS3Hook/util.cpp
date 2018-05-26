#include "util.h"
#include <cstdio>
#include <algorithm>
#include <string>

char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

void print_hex(const char* data, const int len)
{
	const char* p = data;
	for (int i = 0; i < len; p++, i++)
	{
		printf("%c%c ", hex_chars[(*p & 0xF0) >> 4], hex_chars[(*p & 0x0F) >> 0]);
	}
}

std::string random_string(size_t length)
{
	const auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}