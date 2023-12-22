#ifndef PARAMS_H
#define PARAMS_H

#define NID_SECP256K1 714 // OpenSSL NID_secp256k1
#define CURVE "secp256k1" // OpenSSL secp256k1 curve name
#define C_MAX 32          // max length of bid in bits
#define DIVIDER "\n=========================================================\n"
#define PRINT_MESSAGE(msg) std::cout << DIVIDER << msg << DIVIDER << std::endl;

#endif // PARAMS_H
