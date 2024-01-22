#ifndef PARAMS_H
#define PARAMS_H

#define CURVE "secp256k1" // OpenSSL secp256k1 curve name
#define NID_SECP256K1 714 // OpenSSL NID_secp256k1
#define HASH "sha256"     // OpenSSL SHA256 hash function name

#define C_MAX 32 // max length of bid in bits

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define DIVIDER "\n================================================\n"
#define PRINT_MESSAGE(msg)                                                     \
  std::cout << DIVIDER << __FILE__ << ":" << __LINE__ << ": \n"                \
            << msg << DIVIDER << std::endl
#define PRINT_ERROR(msg)                                                       \
  std::cerr << DIVIDER << ANSI_COLOR_RED "[ERROR] " ANSI_COLOR_RESET           \
            << __FILE__ << ":" << __LINE__ << ": \n"                           \
            << msg << DIVIDER << std::endl
#define PRINT_DEBUG(msg)                                                       \
  std::cout << DIVIDER << ANSI_COLOR_YELLOW "[DEBUG] " ANSI_COLOR_RESET        \
            << __FILE__ << ":" << __LINE__ << ": \n"                           \
            << msg << DIVIDER << std::endl

// #define PRINT_INVISABLE(msg) 

#endif // PARAMS_H
