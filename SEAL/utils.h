#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <iomanip>
#include <sstream>

std::string uchar2hex(const unsigned char *data, size_t len);
std::string char2hex(const char *data, size_t len);

#endif // UTILS_H