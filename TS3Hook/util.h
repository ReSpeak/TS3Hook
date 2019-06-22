#ifndef UTIL_H
#define UTIL_H
#include <string>
#include <tuple>

void print_hex(const char* data, const int len);
std::string random_string(size_t length);
std::tuple<size_t, size_t> find_param(std::string str, const char* ptr);

#endif // UTIL_H
