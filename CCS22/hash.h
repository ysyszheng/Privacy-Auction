#ifndef HASH_H
#define HASH_H

#include "params.h"
#include "print.h"
#include <cstddef>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

void handelSHA256Error(EVP_MD_CTX *);

void SHA256inSetup(BIGNUM *h, const BIGNUM *order, const BIGNUM *bns[],
                   size_t array_len, BN_CTX *ctx);

#endif // HASH_H
