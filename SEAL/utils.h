#ifndef UTILS_H
#define UTILS_H

#include <cstddef>
#include <iomanip>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <sstream>

std::string uchar2hex(const unsigned char *data, size_t len);
std::string char2hex(const char *data, size_t len);

// FIXME: calculate hash is right? check the correctness of hash!!!
/**
 * @brief calculate SHA256 hash of data, return SHA256(g, g^v, g^x, id_)
 */
BIGNUM *SHA256inNIZKPoKDLog(const EC_GROUP *group, const BIGNUM *order,
                            const EC_POINT *generator, const EC_POINT *g_to_v,
                            const EC_POINT *g_to_x, size_t id_, BN_CTX *ctx);
/**
 * @brief calculate SHA256 hash of data, return SHA256(g, eps11, eps12, eps21,
 * eps22, phi, A, B id_)
 */
BIGNUM *SHA256inNIZKPoWFCom(const EC_GROUP *group, const BIGNUM *order,
                            const EC_POINT *generator, const EC_POINT *eps11,
                            const EC_POINT *eps12, const EC_POINT *eps21,
                            const EC_POINT *eps22, const EC_POINT *phi,
                            const EC_POINT *A, const EC_POINT *B, size_t id_,
                            BN_CTX *ctx);
/**
 * @brief calculate SHA256 hash of data, return SHA256(g, eps11, eps12, eps13,
 * eps14, eps21, eps22, eps23, eps24, b, X, Y, R, c, A, B, id_)
 */
BIGNUM *SHA256inNIZKPoWFStage1(
    const EC_GROUP *group, const BIGNUM *order, const EC_POINT *generator,
    const EC_POINT *eps11, const EC_POINT *eps12, const EC_POINT *eps13,
    const EC_POINT *eps14, const EC_POINT *eps21, const EC_POINT *eps22,
    const EC_POINT *eps23, const EC_POINT *eps24, const EC_POINT *b,
    const EC_POINT *X, const EC_POINT *Y, const EC_POINT *R, const EC_POINT *c,
    const EC_POINT *A, const EC_POINT *B, size_t id_, BN_CTX *ctx);
/**
 * @brief calculate SHA256 hash of data, return SHA256(g, eps11, eps12, eps13,
 * eps11', eps12', eps21, eps22, eps23, eps21', eps22', eps31, eps32, eps31',
 * eps32', Xi, Xj, A, Bi, Bj, B, Ri, Rj, Ci, Yi, Yj, id_)
 */
BIGNUM *SHA256inNIZKPoWFStage2(
    const EC_GROUP *group, const BIGNUM *order, const EC_POINT *generator,
    const EC_POINT *eps11, const EC_POINT *eps12, const EC_POINT *eps13,
    const EC_POINT *eps11prime, const EC_POINT *eps12prime,
    const EC_POINT *eps13prime, const EC_POINT *eps21, const EC_POINT *eps22,
    const EC_POINT *eps23, const EC_POINT *eps21prime,
    const EC_POINT *eps22prime, const EC_POINT *eps23prime,
    const EC_POINT *eps31, const EC_POINT *eps32, const EC_POINT *eps31prime,
    const EC_POINT *eps32prime, const EC_POINT *Xi, const EC_POINT *Xj,
    const EC_POINT *A, const EC_POINT *Bi, const EC_POINT *Bj,
    const EC_POINT *B, const EC_POINT *Ri, const EC_POINT *Rj,
    const EC_POINT *Ci, const EC_POINT *Yi, const EC_POINT *Yj, size_t id_,
    BN_CTX *ctx);

#endif // UTILS_H