#pragma once

#include <iomanip>
#include <iostream>
#include <sstream>

inline std::string uchar2hex(const unsigned char *data, size_t len) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << static_cast<unsigned>(data[i]);
  }
  return ss.str();
}

inline std::string char2hex(const char *data, size_t len) {
  return uchar2hex(reinterpret_cast<const unsigned char *>(data), len);
}
