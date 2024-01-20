#include "bidder.h"
#include "params.h"
#include "utils.h"
#include <cassert>
#include <cstddef>
#include <cstring>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

using namespace std;

/**
 * @brief Construct a new Bidder object, with a c-bit random bid
 *
 * @param id ID of bidder, should start from 0
 * @param c Number of bits in bid
 */
Bidder::Bidder(size_t id, size_t c, size_t n)
    : id_(id), c_(c), n_(n), maxBid(0), junctionFlag(false), prevDecidingBit(1),
      commitments(c), keys(c) {
  assert(c <= C_MAX);

  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<int> dist(0, (1 << c) - 1);
  bid_ = dist(gen);
  binaryBidStr = bitset<C_MAX>(bid_).to_string().substr(C_MAX - c_);

  PRINT_MESSAGE("Construct Bidder: " << id_ << "\nBid: " << bid_
                                     << ", Bid (in binary): " << binaryBidStr);

  if (NULL == (group = EC_GROUP_new_by_curve_name(NID_SECP256K1))) {
    ERR_print_errors_fp(stderr);
  }
  if (NULL == (generator = EC_GROUP_get0_generator(group))) {
    ERR_print_errors_fp(stderr);
  }
  if (NULL == (order = EC_GROUP_get0_order(group))) {
    ERR_print_errors_fp(stderr);
  }

  curInfo.resize(n);
  prevDecidingInfo.resize(n);
}

/**
 * @brief Returns the ID of the bidder
 *
 * @return size_t
 */
size_t Bidder::getId() { return id_; }

/**
 * @brief Returns the bid of the bidder
 *
 * @return size_t
 */
size_t Bidder::getBid() { return bid_; }

/**
 * @brief Returns the max bid calculated by the bidder during the auction
 *
 * @return size_t
 */
size_t Bidder::getMaxBid() { return maxBid; }

/**
 * @brief Generate a Non-interactive zero-knowledge proof of knowledge of
 * discrete logarithm
 *
 * @param proof NIZKPoKDLog
 * @param g_to_x g^x
 * @param x x, the discrete logarithm
 * @param ctx BN_CTX
 */
void Bidder::genNIZKPoKDLog(NIZKPoKDLog &proof, const EC_POINT *g_to_x,
                            const BIGNUM *x, BN_CTX *ctx) {
  BIGNUM *v = BN_new();   // \bar{r} in paper
  BIGNUM *h = BN_new();   // hash(g, g^v, g^x, id_), ch in paper
  BIGNUM *rho = BN_new(); // hash(g, g^v, g^x, id_), ch in paper
  EC_POINT *g_to_v = EC_POINT_new(group);

  BN_rand_range(v, order);
  EC_POINT_mul(group, g_to_v, v, NULL, NULL, ctx);

  h = SHA256inNIZKPoKDLog(group, order, generator, g_to_v, g_to_x, id_, ctx);

  BN_mod_mul(h, h, x, order, ctx);   // h = h*x = ch*x
  BN_mod_sub(rho, v, h, order, ctx); // rho = v-h = v-ch*x

  proof.eps = g_to_v;
  proof.rho = rho;
}

/**
 * @brief Verify a Non-interactive zero-knowledge proof of knowledge of
 * discrete logarithm
 *
 * @param proof NIZKPoKDLog
 * @param X g^x
 * @param ctx BN_CTX
 * @return true, if proof is valid
 * @return false, otherwise
 */
bool Bidder::verNIZKPoKDLog(NIZKPoKDLog &proof, const EC_POINT *X, size_t id,
                            BN_CTX *ctx) {
  BIGNUM *h = BN_new(); // hash(g, g^v, g^x, id_), ch in paper
  EC_POINT *g_to_rho = EC_POINT_new(group);
  EC_POINT *X_to_h = EC_POINT_new(group);

  h = SHA256inNIZKPoKDLog(group, order, generator, proof.eps, X, id, ctx);

  // check: g^rho * X^h == eps
  EC_POINT_mul(group, g_to_rho, proof.rho, NULL, NULL, ctx);
  EC_POINT_mul(group, X_to_h, NULL, X, h, ctx);
  EC_POINT_add(group, X_to_h, X_to_h, g_to_rho, ctx);
  if (EC_POINT_cmp(group, X_to_h, proof.eps, ctx) != 0) {
    PRINT_ERROR("NIZKPoKDLog verification failed for bidder " << id);
    return false;
  }
  return true;
}

/**
 * @brief Generate a Non-interactive zero-knowledge proof of well-formedness
 * of commitments
 *
 * @param proof NIZKPoWFCom
 * @param phi g^{alpha*beta}
 * @param A g^alpha
 * @param B g^beta
 * @param alpha alpha
 * @param ctx BN_CTX
 */
void Bidder::genNIZKPoWFCom(NIZKPoWFCom &proof, const EC_POINT *phi,
                            const EC_POINT *A, const EC_POINT *B,
                            const BIGNUM *alpha, int bit, BN_CTX *ctx) {
  BIGNUM *r1 = BN_new(); // or r2, no matter
  BIGNUM *rho1 = BN_new();
  BIGNUM *rho2 = BN_new();
  BIGNUM *ch = BN_new();
  BIGNUM *ch1 = BN_new();
  BIGNUM *ch2 = BN_new();

  EC_POINT *eps11 = EC_POINT_new(group);
  EC_POINT *eps12 = EC_POINT_new(group);
  EC_POINT *eps21 = EC_POINT_new(group);
  EC_POINT *eps22 = EC_POINT_new(group);
  EC_POINT *tmp = EC_POINT_new(group);

  BN_rand_range(r1, order);

  if (bit == 0) { // bit = 0
    BN_rand_range(ch2, order);
    BN_rand_range(rho2, order);

    EC_POINT_mul(group, eps11, r1, NULL, NULL, ctx); // eps11 = g^r1

    EC_POINT_mul(group, eps12, NULL, B, r1, ctx); // eps12 = g^(beat*r1)

    EC_POINT_mul(group, eps21, rho2, A, ch2,
                 ctx); // eps21 = g^rho2 * g^(alpha*ch2)

    EC_POINT_copy(tmp, generator);                 // tmp = g
    EC_POINT_invert(group, tmp, ctx);              // tmp = g^-1
    EC_POINT_add(group, tmp, phi, tmp, ctx);       // tmp = phi/g
    EC_POINT_mul(group, tmp, NULL, tmp, ch2, ctx); // tmp = (phi/g)^ch2
    EC_POINT_mul(group, eps22, NULL, B, rho2,
                 ctx); // eps22 = g^(beta*rho2)
    EC_POINT_add(group, eps22, eps22, tmp,
                 ctx); // eps22 = g^(beta*rho2) * (phi/g)^ch2
  } else {             // bit = 1
    BN_rand_range(ch1, order);
    BN_rand_range(rho1, order);

    EC_POINT_mul(group, eps11, rho1, NULL, NULL, ctx); // eps11 = g^rho1
    EC_POINT_mul(group, tmp, NULL, A, ch1, ctx);       // tmp = g^{alpha*ch1}
    EC_POINT_add(group, eps11, eps11, tmp,
                 ctx); // eps11 = g^rho1 * g^(alpha*ch1)

    EC_POINT_mul(group, eps12, NULL, phi, ch1, ctx); // eps12 = phi^ch1
    EC_POINT_mul(group, tmp, NULL, B, rho1, ctx);    // tmp = g^{beta*rho1}
    EC_POINT_add(group, eps12, eps12, tmp,
                 ctx); // eps12 = g^{beta*rho1} * phi^ch1

    EC_POINT_mul(group, eps21, r1, NULL, NULL, ctx); // eps21 = g^r1

    EC_POINT_mul(group, eps22, NULL, B, r1, ctx); // eps22 = g^(beta*r1)
  }

  ch = SHA256inNIZKPoWFCom(group, order, generator, eps11, eps12, eps21, eps22,
                           phi, A, B, id_, ctx);

  if (bit == 0) {
    BN_mod_sub(ch1, ch, ch2, order, ctx);    // ch1 = ch-ch2
    BN_mod_mul(ch1, ch1, alpha, order, ctx); // ch1 = alpha*(ch-ch2)
    BN_mod_sub(rho1, r1, ch1, order, ctx);   // rho1 = r1-alpha*(ch-ch2)
  } else {
    BN_mod_sub(ch2, ch, ch1, order, ctx);    // ch2 = ch-ch1
    BN_mod_mul(ch2, ch2, alpha, order, ctx); // ch2 = alpha*(ch-ch1)
    BN_mod_sub(rho2, r1, ch2, order, ctx);   // rho2 = r1-alpha*(ch-ch1)
    BN_mod_sub(ch2, ch, ch1, order, ctx);    // reset ch2 = ch-ch1
  }

  proof.eps11 = eps11;
  proof.eps12 = eps12;
  proof.eps21 = eps21;
  proof.eps22 = eps22;
  proof.rho1 = rho1;
  proof.rho2 = rho2;
  proof.ch2 = ch2;
}

/**
 * @brief Verify a Non-interactive zero-knowledge proof of well-formedness
 * of commitment
 *
 * @param proof NIZKPoWFCom
 * @param phi
 * @param A
 * @param B
 * @param id
 * @param ctx
 * @return true
 * @return false
 */
bool Bidder::verNIZKPoWFCom(NIZKPoWFCom &proof, const EC_POINT *phi,
                            const EC_POINT *A, const EC_POINT *B, size_t id,
                            BN_CTX *ctx) {
  bool ret = true;
  BIGNUM *ch = BN_new();
  BIGNUM *ch1 = BN_new();
  EC_POINT *tmp1 = EC_POINT_new(group);
  EC_POINT *tmp2 = EC_POINT_new(group);

  ch = SHA256inNIZKPoWFCom(group, order, generator, proof.eps11, proof.eps12,
                           proof.eps21, proof.eps22, phi, A, B, id, ctx);

  BN_mod_sub(ch1, ch, proof.ch2, order, ctx); // ch1 = ch-ch2

  // check 1: g^rho1 * A^ch1 == eps11
  EC_POINT_mul(group, tmp1, proof.rho1, NULL, NULL, ctx); // tmp1 = g^rho1
  EC_POINT_mul(group, tmp2, NULL, A, ch1, ctx);           // tmp2 = A^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho1 * A^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps11, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFCom verification failed for bidder " << id
                                                              << ": check 1");
    ret = false;
  }

  // check 2: B^rho1 * phi^ch1 == eps12
  EC_POINT_mul(group, tmp1, NULL, B, proof.rho1, ctx); // tmp1 = B^rho1
  EC_POINT_mul(group, tmp2, NULL, phi, ch1, ctx);      // tmp2 = phi^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = B^rho1 * phi^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps12, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFCom verification failed for bidder " << id
                                                              << ": check 2");
    ret = false;
  }

  // check 3: g^rho2 * A^ch2 == eps21
  EC_POINT_mul(group, tmp1, proof.rho2, NULL, NULL, ctx); // tmp1 = g^rho2
  EC_POINT_mul(group, tmp2, NULL, A, proof.ch2, ctx);     // tmp2 = A^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho2 * A^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps21, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFCom verification failed for bidder " << id
                                                              << ": check 3");
    ret = false;
  }

  // check 4: B^rho2 * (phi/g)^ch2 == eps22
  EC_POINT_copy(tmp1, generator);                        // tmp1 = g
  EC_POINT_invert(group, tmp1, ctx);                     // tmp1 = g^-1
  EC_POINT_add(group, tmp1, phi, tmp1, ctx);             // tmp1 = phi/g
  EC_POINT_mul(group, tmp1, NULL, tmp1, proof.ch2, ctx); // tmp1 = (phi/g)^ch2
  EC_POINT_mul(group, tmp2, NULL, B, proof.rho2, ctx);   // tmp2 = B^rho2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = B^rho2 * (phi/g)^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps22, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFCom verification failed for bidder " << id
                                                              << ": check 4");
    ret = false;
  }

  return ret;
}

/**
 * @brief Generate a Non-interactive zero-knowledge proof of well-formedness
 * of stage 1
 *
 * @param proof
 * @param b B in paper, encoded bit in current step
 * @param X
 * @param Y
 * @param R
 * @param c phi, c, or C in paper
 * @param A
 * @param B \bar{B} in paper, commitment B in current step
 * @param x
 * @param alpha
 * @param bit
 * @param ctx
 */
void Bidder::genNIZKPoWFStage1(NIZKPoWFStage1 &proof, const EC_POINT *b,
                               const EC_POINT *X, const EC_POINT *Y,
                               const EC_POINT *R, const EC_POINT *c,
                               const EC_POINT *A, const EC_POINT *B,
                               const BIGNUM *x, const BIGNUM *alpha, int bit,
                               BN_CTX *ctx) {
  assert(bit == 0 || bit == 1);

  BIGNUM *r11 = BN_new(); // or r21, no matter
  BIGNUM *r12 = BN_new(); // or r22, no matter
  BIGNUM *rho11 = BN_new();
  BIGNUM *rho12 = BN_new();
  BIGNUM *rho21 = BN_new();
  BIGNUM *rho22 = BN_new();
  BIGNUM *ch = BN_new();
  BIGNUM *ch1 = BN_new();
  BIGNUM *ch2 = BN_new();

  EC_POINT *eps11 = EC_POINT_new(group);
  EC_POINT *eps12 = EC_POINT_new(group);
  EC_POINT *eps13 = EC_POINT_new(group);
  EC_POINT *eps14 = EC_POINT_new(group);
  EC_POINT *eps21 = EC_POINT_new(group);
  EC_POINT *eps22 = EC_POINT_new(group);
  EC_POINT *eps23 = EC_POINT_new(group);
  EC_POINT *eps24 = EC_POINT_new(group);
  EC_POINT *tmp = EC_POINT_new(group);

  BN_rand_range(r11, order);
  BN_rand_range(r12, order);

  if (bit == 0) {
    BN_rand_range(rho21, order);
    BN_rand_range(rho22, order);
    BN_rand_range(ch2, order);

    EC_POINT_mul(group, eps11, r11, NULL, NULL, ctx); // eps11 = g^r11

    EC_POINT_mul(group, eps12, r12, NULL, NULL, ctx); // eps12 = g^r12

    EC_POINT_mul(group, eps13, NULL, Y, r11, ctx); // eps13 = Y^r11

    EC_POINT_mul(group, eps14, NULL, B, r12, ctx); // eps14 = B^r12

    // eps21 = g^rho21 * X^ch2
    EC_POINT_mul(group, eps21, rho21, NULL, NULL, ctx); // eps21 = g^rho21
    EC_POINT_mul(group, tmp, NULL, X, ch2, ctx);        // tmp = X^ch2
    EC_POINT_add(group, eps21, eps21, tmp, ctx); // eps21 = g^rho21 * X^ch2

    // eps22 = g^rho22 * A^ch2
    EC_POINT_mul(group, eps22, rho22, NULL, NULL, ctx); // eps22 = g^rho22
    EC_POINT_mul(group, tmp, NULL, A, ch2, ctx);        // tmp = A^ch2
    EC_POINT_add(group, eps22, eps22, tmp, ctx); // eps22 = g^rho22 * A^ch2

    // eps23 = R^rho21 * B^ch2
    EC_POINT_mul(group, eps23, NULL, R, rho21, ctx); // eps23 = R^rho21
    EC_POINT_mul(group, tmp, NULL, b, ch2, ctx);     // tmp = b^ch2
    EC_POINT_add(group, eps23, eps23, tmp, ctx);     // eps23 = R^rho21 * b^ch2

    // eps24 = B^rho22 * (c/g)^ch2
    EC_POINT_mul(group, eps24, NULL, B, rho22, ctx); // eps24 = B^rho22
    EC_POINT_copy(tmp, generator);                   // tmp = g
    EC_POINT_invert(group, tmp, ctx);                // tmp = g^-1
    EC_POINT_add(group, tmp, c, tmp, ctx);           // tmp = c/g
    EC_POINT_mul(group, tmp, NULL, tmp, ch2, ctx);   // tmp = (c/g)^ch2
    EC_POINT_add(group, eps24, eps24, tmp, ctx); // eps24 = B^rho22 * (c/g)^ch2
  } else {
    BN_rand_range(rho11, order);
    BN_rand_range(rho12, order);
    BN_rand_range(ch1, order);

    // eps11 = g^rho11 * X^ch1
    EC_POINT_mul(group, eps11, rho11, NULL, NULL, ctx); // eps11 = g^rho11
    EC_POINT_mul(group, tmp, NULL, X, ch1, ctx);        // tmp = X^ch1
    EC_POINT_add(group, eps11, eps11, tmp, ctx); // eps11 = g^rho11 * X^ch1

    // eps12 = g^rho12 * A^ch1
    EC_POINT_mul(group, eps12, rho12, NULL, NULL, ctx); // eps12 = g^rho12
    EC_POINT_mul(group, tmp, NULL, A, ch1, ctx);        // tmp = A^ch1
    EC_POINT_add(group, eps12, eps12, tmp, ctx); // eps12 = g^rho12 * A^ch1

    // eps13 = R^rho11 * B^ch1
    EC_POINT_mul(group, eps13, NULL, R, rho11, ctx); // eps13 = R^rho11
    EC_POINT_mul(group, tmp, NULL, b, ch1, ctx);     // tmp = b^ch1
    EC_POINT_add(group, eps13, eps13, tmp, ctx);     // eps13 = R^rho11 * b^ch1

    // eps14 = B^rho12 * c^ch1
    EC_POINT_mul(group, eps14, NULL, B, rho12, ctx); // eps14 = B^rho12
    EC_POINT_mul(group, tmp, NULL, c, ch1, ctx);     // tmp = c^ch1
    EC_POINT_add(group, eps14, eps14, tmp, ctx);     // eps14 = B^rho12 * c^ch1

    EC_POINT_mul(group, eps21, r11, NULL, NULL, ctx); // eps21 = g^r11

    EC_POINT_mul(group, eps22, r12, NULL, NULL, ctx); // eps22 = g^r12

    EC_POINT_mul(group, eps23, NULL, Y, r11, ctx); // eps23 = Y^r11

    EC_POINT_mul(group, eps24, NULL, B, r12, ctx); // eps24 = B^r12
  }

  ch = SHA256inNIZKPoWFStage1(group, order, generator, eps11, eps12, eps13,
                              eps14, eps21, eps22, eps23, eps24, b, X, Y, R, c,
                              A, B, id_, ctx);

  if (bit == 0) {
    BN_mod_sub(ch1, ch, ch2, order, ctx);    // ch1 = ch-ch2
    BN_mod_mul(ch1, ch1, x, order, ctx);     // ch1 = x*(ch-ch2)
    BN_mod_sub(rho11, r11, ch1, order, ctx); // rho11 = r11-x*(ch-ch2)

    BN_mod_sub(ch1, ch, ch2, order, ctx);    // reset ch1 = ch-ch2
    BN_mod_mul(ch1, ch1, alpha, order, ctx); // ch1 = alpha*(ch-ch2)
    BN_mod_sub(rho12, r12, ch1, order, ctx); // rho12 = r12-alpha*(ch-ch2)
  } else {
    BN_mod_sub(ch2, ch, ch1, order, ctx);    // ch2 = ch-ch1
    BN_mod_mul(ch2, ch2, x, order, ctx);     // ch2 = x*(ch-ch1)
    BN_mod_sub(rho21, r11, ch2, order, ctx); // rho21 = r11-x*(ch-ch1)

    BN_mod_sub(ch2, ch, ch1, order, ctx);    // reset ch2 = ch-ch1
    BN_mod_mul(ch2, ch2, alpha, order, ctx); // ch2 = alpha*(ch-ch1)
    BN_mod_sub(rho22, r12, ch2, order, ctx); // rho22 = r12-alpha*(ch-ch1)
  }

  proof.eps11 = eps11;
  proof.eps12 = eps12;
  proof.eps13 = eps13;
  proof.eps14 = eps14;
  proof.eps21 = eps21;
  proof.eps22 = eps22;
  proof.eps23 = eps23;
  proof.eps24 = eps24;
  proof.rho11 = rho11;
  proof.rho12 = rho12;
  proof.rho21 = rho21;
  proof.rho22 = rho22;
  proof.ch2 = ch2;
}

/**
 * @brief Verify a Non-interactive zero-knowledge proof of well-formedness
 * of stage 1
 *
 * @param proof
 * @param b
 * @param X
 * @param Y
 * @param R
 * @param c
 * @param A
 * @param B
 * @param id
 * @param ctx
 * @return true
 * @return false
 */
bool Bidder::verNIZKPoWFStage1(NIZKPoWFStage1 &proof, const EC_POINT *b,
                               const EC_POINT *X, const EC_POINT *Y,
                               const EC_POINT *R, const EC_POINT *c,
                               const EC_POINT *A, const EC_POINT *B, size_t id,
                               BN_CTX *ctx) {
  bool ret = true;
  BIGNUM *ch = BN_new();
  BIGNUM *ch1 = BN_new();
  EC_POINT *tmp1 = EC_POINT_new(group);
  EC_POINT *tmp2 = EC_POINT_new(group);

  ch = SHA256inNIZKPoWFStage1(group, order, generator, proof.eps11, proof.eps12,
                              proof.eps13, proof.eps14, proof.eps21,
                              proof.eps22, proof.eps23, proof.eps24, b, X, Y, R,
                              c, A, B, id, ctx);
  BN_mod_sub(ch1, ch, proof.ch2, order, ctx); // ch1 = ch-ch2

  // check 1: g^rho11 * X^ch1 == eps11
  EC_POINT_mul(group, tmp1, proof.rho11, NULL, NULL, ctx); // tmp1 = g^rho11
  EC_POINT_mul(group, tmp2, NULL, X, ch1, ctx);            // tmp2 = X^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho11 * X^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps11, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage1 verification failed for bidder "
                << id << ": check 1");
    ret = false;
  }

  // check 2: g^rho12 * A^ch1 == eps12
  EC_POINT_mul(group, tmp1, proof.rho12, NULL, NULL, ctx); // tmp1 = g^rho12
  EC_POINT_mul(group, tmp2, NULL, A, ch1, ctx);            // tmp2 = A^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho12 * A^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps12, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage1 verification failed for bidder "
                << id << ": check 2");
    ret = false;
  }

  // check 3: Y^rho11 * b^ch1 == eps13
  EC_POINT_mul(group, tmp1, NULL, Y, proof.rho11, ctx); // tmp1 = Y^rho11
  EC_POINT_mul(group, tmp2, NULL, b, ch1, ctx);         // tmp2 = b^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = Y^rho11 * b^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps13, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage1 verification failed for bidder "
                << id << ": check 3");
    ret = false;
  }

  // check 4: B^rho12 * c^ch1 == eps14
  EC_POINT_mul(group, tmp1, NULL, B, proof.rho12, ctx); // tmp1 = B^rho12
  EC_POINT_mul(group, tmp2, NULL, c, ch1, ctx);         // tmp2 = c^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = B^rho12 * c^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps14, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage1 verification failed for bidder "
                << id << ": check 4");
    ret = false;
  }

  // check 5: g^rho21 * X^ch2 == eps21
  EC_POINT_mul(group, tmp1, proof.rho21, NULL, NULL, ctx); // tmp1 = g^rho21
  EC_POINT_mul(group, tmp2, NULL, X, proof.ch2, ctx);      // tmp2 = X^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho21 * X^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps21, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage1 verification failed for bidder "
                << id << ": check 5");
    ret = false;
  }

  // check 6: g^rho22 * A^ch2 == eps22
  EC_POINT_mul(group, tmp1, proof.rho22, NULL, NULL, ctx); // tmp1 = g^rho22
  EC_POINT_mul(group, tmp2, NULL, A, proof.ch2, ctx);      // tmp2 = A^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho22 * A^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps22, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage1 verification failed for bidder "
                << id << ": check 6");
    ret = false;
  }

  // check 7: R^rho21 * b^ch2 == eps23
  EC_POINT_mul(group, tmp1, NULL, R, proof.rho21, ctx); // tmp1 = R^rho21
  EC_POINT_mul(group, tmp2, NULL, b, proof.ch2, ctx);   // tmp2 = b^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = R^rho21 * b^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps23, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage1 verification failed for bidder "
                << id << ": check 7");
    ret = false;
  }

  // check 8: B^rho22 * (c/g)^ch2 == eps24
  EC_POINT_mul(group, tmp1, NULL, B, proof.rho22, ctx);  // tmp1 = B^rho22
  EC_POINT_copy(tmp2, generator);                        // tmp2 = g
  EC_POINT_invert(group, tmp2, ctx);                     // tmp2 = g^-1
  EC_POINT_add(group, tmp2, c, tmp2, ctx);               // tmp2 = c/g
  EC_POINT_mul(group, tmp2, NULL, tmp2, proof.ch2, ctx); // tmp2 = (c/g)^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = B^rho22 * (c/g)^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps24, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage1 verification failed for bidder "
                << id << ": check 8");
    ret = false;
  }

  return ret;
}

/**
 * @brief Generate a Non-interactive zero-knowledge proof of well-formedness
 * of stage 1
 *
 * @param proof result NIZKPoWFStage2
 * @param Bi encoded bit in current step
 * @param Xi public key X in current step
 * @param Ri public key R in current step
 * @param Bj encoded bit in previous step
 * @param Xj public key X in previous step
 * @param Rj public key R in previous step
 * @param Ci commitment phi in current step
 * @param A commitment A in current step
 * @param B commitment B in current step
 * ($Y=\frac{\prod_{i=1}^{id-1}X_j}{\prod_{i=id+1}^{n}X_j}$)
 * @param Yi Y in current step
 * @param Yj Y in previous step
 * @param xi private key x in current step
 * @param xj private key x in previous step
 * @param alphai random element alpha used in commitment of current step
 * @param bi (plaintext) bit in current step
 * @param bj (plaintext) bit in previous step
 * @param ctx
 */
void Bidder::genNIZKPoWFStage2(
    NIZKPoWFStage2 &proof, const EC_POINT *Bi, const EC_POINT *Xi,
    const EC_POINT *Ri, const EC_POINT *Bj, const EC_POINT *Xj,
    const EC_POINT *Rj, const EC_POINT *Ci, const EC_POINT *A,
    const EC_POINT *B, const EC_POINT *Yi, const EC_POINT *Yj, const BIGNUM *xi,
    const BIGNUM *xj, const BIGNUM *alphai, int bi, int bj, BN_CTX *ctx) {
  assert((bi == 0 || bi == 1) && (bj == 0 || bj == 1));

  BIGNUM *r11 = BN_new(); // or r21, r31, no matter
  BIGNUM *r12 = BN_new(); // or r22, r32, no matter
  BIGNUM *r13 = BN_new(); // or r23, no matter, don't need r33
  BIGNUM *rho11 = BN_new();
  BIGNUM *rho12 = BN_new();
  BIGNUM *rho13 = BN_new();
  BIGNUM *rho21 = BN_new();
  BIGNUM *rho22 = BN_new();
  BIGNUM *rho23 = BN_new();
  BIGNUM *rho31 = BN_new();
  BIGNUM *rho32 = BN_new();
  BIGNUM *rho33 = BN_new();
  BIGNUM *ch = BN_new();
  BIGNUM *ch1 = BN_new();
  BIGNUM *ch2 = BN_new();
  BIGNUM *ch3 = BN_new();
  BIGNUM *chtmp = BN_new();

  EC_POINT *eps11 = EC_POINT_new(group);
  EC_POINT *eps12 = EC_POINT_new(group);
  EC_POINT *eps13 = EC_POINT_new(group);
  EC_POINT *eps11prime = EC_POINT_new(group);
  EC_POINT *eps12prime = EC_POINT_new(group);
  EC_POINT *eps13prime = EC_POINT_new(group);
  EC_POINT *eps21 = EC_POINT_new(group);
  EC_POINT *eps22 = EC_POINT_new(group);
  EC_POINT *eps23 = EC_POINT_new(group);
  EC_POINT *eps21prime = EC_POINT_new(group);
  EC_POINT *eps22prime = EC_POINT_new(group);
  EC_POINT *eps23prime = EC_POINT_new(group);
  EC_POINT *eps31 = EC_POINT_new(group);
  EC_POINT *eps32 = EC_POINT_new(group);
  EC_POINT *eps31prime = EC_POINT_new(group);
  EC_POINT *eps32prime = EC_POINT_new(group);
  EC_POINT *tmp = EC_POINT_new(group);

  BN_rand_range(r11, order);
  BN_rand_range(r12, order);
  BN_rand_range(r13, order);

  if (bi == 1) { // => bj == 1
    BN_rand_range(rho21, order);
    BN_rand_range(rho22, order);
    BN_rand_range(rho23, order);
    BN_rand_range(rho31, order);
    BN_rand_range(rho32, order);
    BN_rand_range(rho33, order);
    BN_rand_range(ch2, order);
    BN_rand_range(ch3, order);

    EC_POINT_mul(group, eps11, r11, NULL, NULL, ctx);    // eps11 = g^r11
    EC_POINT_mul(group, eps12, r12, NULL, NULL, ctx);    // eps12 = g^r12
    EC_POINT_mul(group, eps13, r13, NULL, NULL, ctx);    // eps13 = g^r13
    EC_POINT_mul(group, eps11prime, NULL, Ri, r11, ctx); // eps11' = Ri^r11
    EC_POINT_mul(group, eps12prime, NULL, Rj, r12, ctx); // eps12' = Rj^r12
    EC_POINT_mul(group, eps11prime, NULL, B, r13, ctx);  // eps13' = B^r13

    EC_POINT_mul(group, eps21, rho21, Xi, ch2, ctx); // eps21 = g^rho21 * Xi^ch2
    EC_POINT_mul(group, eps22, rho22, Xj, ch2, ctx); // eps22 = g^rho22 * Xj^ch2
    EC_POINT_mul(group, eps23, rho23, A, ch2, ctx);  // eps23 = g^rho23 * A^ch2
    // eps21' = Yi^rho21 * Bi^ch2
    EC_POINT_mul(group, eps21prime, NULL, Yi, rho21, ctx);
    EC_POINT_mul(group, tmp, NULL, Bi, ch2, ctx);
    EC_POINT_add(group, eps21prime, eps21prime, tmp, ctx);
    // eps22' = Rj^rho22 * Bj^ch2
    EC_POINT_mul(group, eps22prime, NULL, Rj, rho22, ctx);
    EC_POINT_mul(group, tmp, NULL, Bj, ch2, ctx);
    EC_POINT_add(group, eps22prime, eps22prime, tmp, ctx);
    // eps23' = B^rho23 * Ci^ch2
    EC_POINT_mul(group, eps23prime, NULL, B, rho23, ctx);
    EC_POINT_mul(group, tmp, NULL, Ci, ch2, ctx);
    EC_POINT_add(group, eps23prime, eps23prime, tmp, ctx);

    EC_POINT_mul(group, eps31, rho31, Xi, ch3, ctx); // eps31 = g^rho31 * Xi^ch3
    EC_POINT_mul(group, eps32, rho32, Xj, ch3, ctx); // eps32 = g^rho32 * Xj^ch3
    // eps31' = Yi^rho31 * Bi^ch3
    EC_POINT_mul(group, eps31prime, NULL, Yi, rho31, ctx);
    EC_POINT_mul(group, tmp, NULL, Bi, ch3, ctx);
    EC_POINT_add(group, eps31prime, eps31prime, tmp, ctx);
    // eps32' = Yj^rho32 * Bj^ch3
    EC_POINT_mul(group, eps32prime, NULL, Yj, rho32, ctx);
    EC_POINT_mul(group, tmp, NULL, Bj, ch3, ctx);
    EC_POINT_add(group, eps32prime, eps32prime, tmp, ctx);
  } else { // bi == 0
    if (bj == 1) {
      BN_rand_range(rho11, order);
      BN_rand_range(rho12, order);
      BN_rand_range(rho13, order);
      BN_rand_range(rho31, order);
      BN_rand_range(rho32, order);
      BN_rand_range(rho33, order);
      BN_rand_range(ch1, order);
      BN_rand_range(ch3, order);

      EC_POINT_mul(group, eps21, r11, NULL, NULL, ctx);    // eps21 = g^r11
      EC_POINT_mul(group, eps22, r12, NULL, NULL, ctx);    // eps22 = g^r12
      EC_POINT_mul(group, eps23, r13, NULL, NULL, ctx);    // eps23 = g^r13
      EC_POINT_mul(group, eps21prime, NULL, Yi, r11, ctx); // eps21' = Yi^r11
      EC_POINT_mul(group, eps22prime, NULL, Rj, r12, ctx); // eps22' = Rj^r12
      EC_POINT_mul(group, eps23prime, NULL, B, r13, ctx);  // eps22' = B^r13

      // eps11 = g^rho11 * Xi^ch1
      EC_POINT_mul(group, eps11, rho11, NULL, NULL, ctx); // eps11 = g^rho11
      EC_POINT_mul(group, tmp, NULL, Xi, ch1, ctx);       // tmp = Xi^ch1
      EC_POINT_add(group, eps11, eps11, tmp, ctx); // eps11 = g^rho11 * Xi^ch1
      // eps12 = g^rho12 * Xj^ch1
      EC_POINT_mul(group, eps12, rho12, NULL, NULL, ctx); // eps12 = g^rho12
      EC_POINT_mul(group, tmp, NULL, Xj, ch1, ctx);       // tmp = Xj^ch1
      EC_POINT_add(group, eps12, eps12, tmp, ctx); // eps12 = g^rho12 * Xj^ch1
      // eps13 = g^rho13 * A^ch1
      EC_POINT_mul(group, eps13, rho13, NULL, NULL, ctx); // eps13 = g^rho13
      EC_POINT_mul(group, tmp, NULL, A, ch1, ctx);        // tmp = A^ch1
      EC_POINT_add(group, eps13, eps13, tmp, ctx); // eps13 = g^rho13 * A^ch1
      // eps11' = Ri^rho11 * Bi^ch1
      EC_POINT_mul(group, eps11prime, NULL, Ri, rho11, ctx);
      EC_POINT_mul(group, tmp, NULL, Bi, ch1, ctx);
      EC_POINT_add(group, eps11prime, eps11prime, tmp, ctx);
      // eps12' = Rj^rho12 * Bj^ch1
      EC_POINT_mul(group, eps12prime, NULL, Rj, rho12, ctx);
      EC_POINT_mul(group, tmp, NULL, Bj, ch1, ctx);
      EC_POINT_add(group, eps12prime, eps12prime, tmp, ctx);
      // eps13' = B^rho13 * (Ci/g)^ch1
      EC_POINT_mul(group, eps13prime, NULL, B, rho13, ctx);
      EC_POINT_copy(tmp, generator);                 // tmp = g
      EC_POINT_invert(group, tmp, ctx);              // tmp = g^-1
      EC_POINT_add(group, tmp, Ci, tmp, ctx);        // tmp = Ci/g
      EC_POINT_mul(group, tmp, NULL, tmp, ch1, ctx); // tmp = (Ci/g)^ch1
      EC_POINT_add(group, eps13prime, eps13prime, tmp, ctx);

      EC_POINT_mul(group, eps31, rho31, Xi, ch3,
                   ctx); // eps31 = g^rho31 * Xi^ch3
      EC_POINT_mul(group, eps32, rho32, Xj, ch3,
                   ctx); // eps32 = g^rho32 * Xj^ch3
      // eps31' = Yi^rho31 * Bi^ch3
      EC_POINT_mul(group, eps31prime, NULL, Yi, rho31, ctx);
      EC_POINT_mul(group, tmp, NULL, Bi, ch3, ctx);
      EC_POINT_add(group, eps31prime, eps31prime, tmp, ctx);
      // eps32' = Yj^rho32 * Bj^ch3
      EC_POINT_mul(group, eps32prime, NULL, Yj, rho32, ctx);
      EC_POINT_mul(group, tmp, NULL, Bj, ch3, ctx);
      EC_POINT_add(group, eps32prime, eps32prime, tmp, ctx);
    } else { // bj == 0
      BN_rand_range(rho21, order);
      BN_rand_range(rho22, order);
      BN_rand_range(rho23, order);
      BN_rand_range(rho21, order);
      BN_rand_range(rho22, order);
      BN_rand_range(rho23, order);
      BN_rand_range(ch1, order);
      BN_rand_range(ch2, order);

      EC_POINT_mul(group, eps31, r11, NULL, NULL, ctx);    // eps31 = g^r11
      EC_POINT_mul(group, eps32, r12, NULL, NULL, ctx);    // eps32 = g^r12
      EC_POINT_mul(group, eps31prime, NULL, Yi, r11, ctx); // eps31' = Yi^r11
      EC_POINT_mul(group, eps32prime, NULL, Yj, r12, ctx); // eps32' = Yj^r12

      // eps11 = g^rho11 * Xi^ch1
      EC_POINT_mul(group, eps11, rho11, NULL, NULL, ctx); // eps11 = g^rho11
      EC_POINT_mul(group, tmp, NULL, Xi, ch1, ctx);       // tmp = Xi^ch1
      EC_POINT_add(group, eps11, eps11, tmp, ctx); // eps11 = g^rho11 * Xi^ch1
      // eps12 = g^rho12 * Xj^ch1
      EC_POINT_mul(group, eps12, rho12, NULL, NULL, ctx); // eps12 = g^rho12
      EC_POINT_mul(group, tmp, NULL, Xj, ch1, ctx);       // tmp = Xj^ch1
      EC_POINT_add(group, eps12, eps12, tmp, ctx); // eps12 = g^rho12 * Xj^ch1
      // eps13 = g^rho13 * A^ch1
      EC_POINT_mul(group, eps13, rho13, NULL, NULL, ctx); // eps13 = g^rho13
      EC_POINT_mul(group, tmp, NULL, A, ch1, ctx);        // tmp = A^ch1
      EC_POINT_add(group, eps13, eps13, tmp, ctx); // eps13 = g^rho13 * A^ch1
      // eps11' = Ri^rho11 * Bi^ch1
      EC_POINT_mul(group, eps11prime, NULL, Ri, rho11, ctx);
      EC_POINT_mul(group, tmp, NULL, Bi, ch1, ctx);
      EC_POINT_add(group, eps11prime, eps11prime, tmp, ctx);
      // eps12' = Rj^rho12 * Bj^ch1
      EC_POINT_mul(group, eps12prime, NULL, Rj, rho12, ctx);
      EC_POINT_mul(group, tmp, NULL, Bj, ch1, ctx);
      EC_POINT_add(group, eps12prime, eps12prime, tmp, ctx);
      // eps13' = B^rho13 * (Ci/g)^ch1
      EC_POINT_mul(group, eps13prime, NULL, B, rho13, ctx);
      EC_POINT_copy(tmp, generator);                 // tmp = g
      EC_POINT_invert(group, tmp, ctx);              // tmp = g^-1
      EC_POINT_add(group, tmp, Ci, tmp, ctx);        // tmp = Ci/g
      EC_POINT_mul(group, tmp, NULL, tmp, ch1, ctx); // tmp = (Ci/g)^ch1
      EC_POINT_add(group, eps13prime, eps13prime, tmp, ctx);

      // eps21 = g^rho21 * Xi^ch2
      EC_POINT_mul(group, eps21, rho21, NULL, NULL, ctx); // eps21 = g^rho21
      EC_POINT_mul(group, tmp, NULL, Xi, ch2, ctx);       // tmp = Xi^ch2
      EC_POINT_add(group, eps21, eps21, tmp, ctx); // eps21 = g^rho21 * Xi^ch2
      // eps22 = g^rho22 * Xj^ch2
      EC_POINT_mul(group, eps22, rho22, NULL, NULL, ctx); // eps22 = g^rho22
      EC_POINT_mul(group, tmp, NULL, Xj, ch2, ctx);       // tmp = Xj^ch2
      EC_POINT_add(group, eps22, eps22, tmp, ctx); // eps22 = g^rho22 * Xj^ch2
      // eps23 = g^rho23 * A^ch2
      EC_POINT_mul(group, eps23, rho23, NULL, NULL, ctx); // eps23 = g^rho23
      EC_POINT_mul(group, tmp, NULL, A, ch2, ctx);        // tmp = A^ch2
      EC_POINT_add(group, eps23, eps23, tmp, ctx); // eps23 = g^rho23 * A^ch2
      // eps21' = Yi^rho21 * Bi^ch2
      EC_POINT_mul(group, eps21prime, NULL, Yi, rho21, ctx);
      EC_POINT_mul(group, tmp, NULL, Bi, ch2, ctx);
      EC_POINT_add(group, eps21prime, eps21prime, tmp, ctx);
      // eps22' = Rj^rho22 * Bj^ch2
      EC_POINT_mul(group, eps22prime, NULL, Rj, rho22, ctx);
      EC_POINT_mul(group, tmp, NULL, Bj, ch2, ctx);
      EC_POINT_add(group, eps22prime, eps22prime, tmp, ctx);
      // eps23' = B^rho23 * Ci^ch2
      EC_POINT_mul(group, eps23prime, NULL, B, rho23, ctx);
      EC_POINT_mul(group, tmp, NULL, Ci, ch2, ctx);
      EC_POINT_add(group, eps23prime, eps23prime, tmp, ctx);
    }
  }

  ch = SHA256inNIZKPoWFStage2(group, order, generator, eps11, eps12, eps13,
                              eps11prime, eps12prime, eps13prime, eps21, eps22,
                              eps23, eps21prime, eps22prime, eps23prime, eps31,
                              eps32, eps31prime, eps32prime, Xi, Xj, A, Bi, Bj,
                              B, Ri, Rj, Ci, Yi, Yj, id_, ctx);

  if (bi == 1) { // => bj == 1
    // ch1 = ch-ch2-ch3
    BN_mod_sub(ch1, ch, ch2, order, ctx);  // ch1 = ch-ch2
    BN_mod_sub(ch1, ch1, ch3, order, ctx); // ch1 = ch-ch2-ch3
    // rho11 = r11-xi*ch1
    BN_mod_mul(chtmp, xi, ch1, order, ctx);    // chtmp = xi*ch1
    BN_mod_sub(rho11, r11, chtmp, order, ctx); // rho11 = r11-xi*ch1
    // rho12 = r12-xj*ch1
    BN_mod_mul(chtmp, xj, ch1, order, ctx);    // chtmp = xj*ch1
    BN_mod_sub(rho12, r12, chtmp, order, ctx); // rho12 = r12-xj*ch1
    // rho13 = r13-alphai*ch1
    BN_mod_mul(chtmp, alphai, ch1, order, ctx); // chtmp = alphai*ch1
    BN_mod_sub(rho13, r13, chtmp, order, ctx);  // rho13 = r13-alphai*ch1
  } else {                                      // bi == 0
    if (bj == 1) {
      // ch2 = ch-ch1-ch3
      BN_mod_sub(ch2, ch, ch1, order, ctx);  // ch2 = ch-ch1
      BN_mod_sub(ch2, ch2, ch3, order, ctx); // ch2 = ch-ch1-ch3
      // rho21 = r11-xi*ch2
      BN_mod_mul(chtmp, xi, ch2, order, ctx);    // chtmp = xi*ch2
      BN_mod_sub(rho21, r11, chtmp, order, ctx); // rho21 = r11-xi*ch2
      // rho22 = r12-xj*ch2
      BN_mod_mul(chtmp, xj, ch2, order, ctx);    // chtmp = xj*ch2
      BN_mod_sub(rho22, r12, chtmp, order, ctx); // rho22 = r12-xj*ch2
      // rho23 = r13-alphai*ch2
      BN_mod_mul(chtmp, alphai, ch2, order, ctx); // chtmp = alphai*ch2
      BN_mod_sub(rho23, r13, chtmp, order, ctx);  // rho23 = r13-alphai*ch2
    } else {                                      // bj == 0
      // ch3 = ch-ch1-ch2
      BN_mod_sub(ch3, ch, ch1, order, ctx);  // ch3 = ch-ch1
      BN_mod_sub(ch3, ch3, ch2, order, ctx); // ch3 = ch-ch1-ch2
      // rho31 = r11-xi*ch3
      BN_mod_mul(chtmp, xi, ch3, order, ctx);    // chtmp = xi*ch3
      BN_mod_sub(rho31, r11, chtmp, order, ctx); // rho31 = r11-xi*ch3
      // rho32 = r12-xj*ch3
      BN_mod_mul(chtmp, xj, ch3, order, ctx);    // chtmp = xj*ch3
      BN_mod_sub(rho32, r12, chtmp, order, ctx); // rho32 = r12-xj*ch3
    }
  }

  proof.eps11 = eps11;
  proof.eps12 = eps12;
  proof.eps13 = eps13;
  proof.eps11prime = eps11prime;
  proof.eps12prime = eps12prime;
  proof.eps13prime = eps13prime;
  proof.eps21 = eps21;
  proof.eps22 = eps22;
  proof.eps23 = eps23;
  proof.eps21prime = eps21prime;
  proof.eps22prime = eps22prime;
  proof.eps23prime = eps23prime;
  proof.eps31 = eps31;
  proof.eps32 = eps32;
  proof.eps31prime = eps31prime;
  proof.eps32prime = eps32prime;
  proof.rho11 = rho11;
  proof.rho12 = rho12;
  proof.rho13 = rho13;
  proof.rho21 = rho21;
  proof.rho22 = rho22;
  proof.rho23 = rho23;
  proof.rho31 = rho31;
  proof.rho32 = rho32;
  proof.ch2 = ch2;
  proof.ch3 = ch3;
}

/**
 * @brief Verify a Non-interactive zero-knowledge proof of well-formedness
 * of stage 2
 *
 * @param proof
 * @param Bi
 * @param Xi
 * @param Ri
 * @param Bj
 * @param Xj
 * @param Rj
 * @param Ci
 * @param A
 * @param B
 * @param Yi
 * @param Yj
 * @param id
 * @param ctx
 * @return true
 * @return false
 */
bool Bidder::verNIZKPoWFStage2(NIZKPoWFStage2 &proof, const EC_POINT *Bi,
                               const EC_POINT *Xi, const EC_POINT *Ri,
                               const EC_POINT *Bj, const EC_POINT *Xj,
                               const EC_POINT *Rj, const EC_POINT *Ci,
                               const EC_POINT *A, const EC_POINT *B,
                               const EC_POINT *Yi, const EC_POINT *Yj,
                               size_t id, BN_CTX *ctx) {
  bool ret = true;
  BIGNUM *ch = BN_new();
  BIGNUM *ch1 = BN_new();
  BIGNUM *ch2 = BN_new();
  BIGNUM *ch3 = BN_new();
  EC_POINT *tmp1 = EC_POINT_new(group);
  EC_POINT *tmp2 = EC_POINT_new(group);

  ch = SHA256inNIZKPoWFStage2(
      group, order, generator, proof.eps11, proof.eps12, proof.eps13,
      proof.eps11prime, proof.eps12prime, proof.eps13prime, proof.eps21,
      proof.eps22, proof.eps23, proof.eps21prime, proof.eps22prime,
      proof.eps23prime, proof.eps31, proof.eps32, proof.eps31prime,
      proof.eps32prime, Xi, Xj, A, Bi, Bj, B, Ri, Rj, Ci, Yi, Yj, id, ctx);
  BN_mod_sub(ch1, ch, proof.ch2, order, ctx);  // ch1 = ch-ch2
  BN_mod_sub(ch1, ch1, proof.ch3, order, ctx); // ch1 = ch-ch2-ch3

  // check 1: g^rho11 * Xi^ch1 == eps11
  EC_POINT_mul(group, tmp1, proof.rho11, NULL, NULL, ctx); // tmp1 = g^rho11
  EC_POINT_mul(group, tmp2, NULL, Xi, ch1, ctx);           // tmp2 = Xi^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho11 * Xi^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps11, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 1");
    ret = false;
  }

  // check 2: g^rho12 * Xj^ch1 == eps12
  EC_POINT_mul(group, tmp1, proof.rho12, NULL, NULL, ctx); // tmp1 = g^rho12
  EC_POINT_mul(group, tmp2, NULL, Xj, ch1, ctx);           // tmp2 = Xj^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho12 * Xj^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps12, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 2");
    ret = false;
  }

  // check 3: g^rho13 * A^ch1 == eps13
  EC_POINT_mul(group, tmp1, proof.rho13, NULL, NULL, ctx); // tmp1 = g^rho13
  EC_POINT_mul(group, tmp2, NULL, A, ch1, ctx);            // tmp2 = A^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho13 * A^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps13, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 3");
    ret = false;
  }

  // check 4: Ri^rho11 * Bi^ch1 == eps11prime
  EC_POINT_mul(group, tmp1, NULL, Ri, proof.rho11, ctx); // tmp1 = Ri^rho11
  EC_POINT_mul(group, tmp2, NULL, Bi, ch1, ctx);         // tmp2 = Bi^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = Ri^rho11 * Bi^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps11prime, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 4");
    ret = false;
  }

  // check 5: Rj^rho12 * Bj^ch1 == eps12prime
  EC_POINT_mul(group, tmp1, NULL, Rj, proof.rho12, ctx); // tmp1 = Rj^rho12
  EC_POINT_mul(group, tmp2, NULL, Bj, ch1, ctx);         // tmp2 = Bj^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = Rj^rho12 * Bj^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps12prime, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 5");
    ret = false;
  }

  // check 6: B^rho13 * (Ci/g)^ch1 == eps13prime
  EC_POINT_mul(group, tmp1, NULL, B, proof.rho13, ctx); // tmp1 = B^rho13
  EC_POINT_copy(tmp2, generator);                       // tmp2 = g
  EC_POINT_invert(group, tmp2, ctx);                    // tmp2 = g^-1
  EC_POINT_add(group, tmp2, Ci, tmp2, ctx);             // tmp2 = Ci/g
  EC_POINT_mul(group, tmp2, NULL, tmp2, ch1, ctx);      // tmp2 = (Ci/g)^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = B^rho13 * (Ci/g)^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps13prime, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 6");
    ret = false;
  }

  // check 7: g^rho21 * Xi^ch2 == eps21
  EC_POINT_mul(group, tmp1, proof.rho21, NULL, NULL, ctx); // tmp1 = g^rho21
  EC_POINT_mul(group, tmp2, NULL, Xi, ch2, ctx);           // tmp2 = Xi^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho21 * Xi^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps21, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 7");
    ret = false;
  }

  // check 8: g^rho22 * Xj^ch2 == eps22
  EC_POINT_mul(group, tmp1, proof.rho22, NULL, NULL, ctx); // tmp1 = g^rho22
  EC_POINT_mul(group, tmp2, NULL, Xj, ch2, ctx);           // tmp2 = Xj^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho22 * Xj^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps22, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 8");
    ret = false;
  }

  // check 9: g^rho23 * A^ch2 == eps23
  EC_POINT_mul(group, tmp1, proof.rho23, NULL, NULL, ctx); // tmp1 = g^rho23
  EC_POINT_mul(group, tmp2, NULL, A, ch2, ctx);            // tmp2 = A^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho23 * A^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps23, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 9");
    ret = false;
  }

  // check 10: Yi^rho21 * Bi^ch2 == eps21prime
  EC_POINT_mul(group, tmp1, NULL, Yi, proof.rho21, ctx); // tmp1 = Yi^rho21
  EC_POINT_mul(group, tmp2, NULL, Bi, ch2, ctx);         // tmp2 = Bi^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = Yi^rho21 * Bi^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps21prime, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 10");
    ret = false;
  }

  // check 11: Rj^rho22 * Bj^ch2 == eps22prime
  EC_POINT_mul(group, tmp1, NULL, Rj, proof.rho22, ctx); // tmp1 = Rj^rho22
  EC_POINT_mul(group, tmp2, NULL, Bj, ch2, ctx);         // tmp2 = Bj^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = Rj^rho22 * Bj^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps22prime, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 11");
    ret = false;
  }

  // check 12: B^rho23 * Ci^ch2 == eps23prime
  EC_POINT_mul(group, tmp1, NULL, B, proof.rho23, ctx); // tmp1 = B^rho23
  EC_POINT_mul(group, tmp2, NULL, Ci, ch2, ctx);        // tmp2 = Ci^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = B^rho23 * Ci^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps23prime, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 12");
    ret = false;
  }

  // check 13: g^rho31 * Xi^ch3 == eps31
  EC_POINT_mul(group, tmp1, proof.rho31, NULL, NULL, ctx); // tmp1 = g^rho31
  EC_POINT_mul(group, tmp2, NULL, Xi, ch3, ctx);           // tmp2 = Xi^ch3
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho31 * Xi^ch3
  if (EC_POINT_cmp(group, tmp2, proof.eps31, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 13");
    ret = false;
  }

  // check 14: g^rho32 * Xj^ch3 == eps32
  EC_POINT_mul(group, tmp1, proof.rho32, NULL, NULL, ctx); // tmp1 = g^rho32
  EC_POINT_mul(group, tmp2, NULL, Xj, ch3, ctx);           // tmp2 = Xj^ch3
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho32 * Xj^ch3
  if (EC_POINT_cmp(group, tmp2, proof.eps32, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 14");
    ret = false;
  }

  // check 15: Yi^rho31 * Bi^ch3 == eps31prime
  EC_POINT_mul(group, tmp1, NULL, Yi, proof.rho31, ctx); // tmp1 = Yi^rho31
  EC_POINT_mul(group, tmp2, NULL, Bi, ch3, ctx);         // tmp2 = Bi^ch3
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = Yi^rho31 * Bi^ch3
  if (EC_POINT_cmp(group, tmp2, proof.eps31prime, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 15");
    ret = false;
  }

  // check 16: Yj^rho32 * Bj^ch3 == eps32prime
  EC_POINT_mul(group, tmp1, NULL, Yj, proof.rho32, ctx); // tmp1 = Yj^rho32
  EC_POINT_mul(group, tmp2, NULL, Bj, ch3, ctx);         // tmp2 = Bj^ch3
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = Yj^rho32 * Bj^ch3
  if (EC_POINT_cmp(group, tmp2, proof.eps32prime, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFStage2 verification failed for bidder "
                << id << ": check 16");
    ret = false;
  }

  return ret;
}

/**
 * @brief In the Commit phase, bidders commit their bids to the public
 * bulletin board, as well as their NIZK
 *
 * @return CommitmentPub, i.e. std::vector<CommitmentPerBit>
 */
CommitmentPub Bidder::commitBid() {
  CommitmentPub pubs(c_);
  int bit;

  for (size_t i = 0; i < c_; ++i) {
    // Commitment of i-th bit of bid_
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bit_value = BN_new();

    BIGNUM *alpha = BN_new();
    BIGNUM *beta = BN_new();
    BIGNUM *alpha_mul_beta = BN_new();

    EC_POINT *commitmentPhi = EC_POINT_new(group);
    EC_POINT *commitmentA = EC_POINT_new(group);
    EC_POINT *commitmentB = EC_POINT_new(group);

    bit = binaryBidStr[i] - '0';
    BN_set_word(bit_value, bit);

    BN_rand_range(alpha, order);
    BN_rand_range(beta, order);
    BN_mul(alpha_mul_beta, alpha, beta, ctx);

    EC_POINT_mul(group, commitmentPhi, alpha_mul_beta, generator, bit_value,
                 ctx);
    EC_POINT_mul(group, commitmentA, alpha, NULL, NULL, ctx);
    EC_POINT_mul(group, commitmentB, beta, NULL, NULL, ctx);

    commitments[i].phi = commitmentPhi;
    commitments[i].A = commitmentA;
    commitments[i].B = commitmentB;
    commitments[i].alpha = alpha;
    commitments[i].beta = beta;

    pubs[i].phi = commitmentPhi;
    pubs[i].A = commitmentA;
    pubs[i].B = commitmentB;

    // Generate NIZKoKDLog
    genNIZKPoKDLog(pubs[i].pokdlogA, commitmentA, alpha, ctx);
    genNIZKPoKDLog(pubs[i].pokdlogB, commitmentB, beta, ctx);

    // Generate NIZKoWFCom
    genNIZKPoWFCom(pubs[i].powfcom, commitmentPhi, commitmentA, commitmentB,
                   alpha, bit, ctx);
  }

  return pubs;
}

/**
 * @brief Verify the commitments of all bidders
 *
 * @param pubs CommitmentPub in order of bidders id, including self
 * @return bool, true if all commitments are valid and NIZK Proofs is valid,
 * false otherwise
 */
bool Bidder::verifyCommitment(std::vector<CommitmentPub> pubs) {
  bool ret = true;
  commitmentsBB = pubs;

  BN_CTX *ctx = BN_CTX_new();
  for (size_t i = 0; i < pubs.size(); ++i) {
    if (i != id_) {
      for (size_t j = 0; j < c_; ++j) {
        // Verify NIZKoKDLog
        ret &= verNIZKPoKDLog(pubs[i][j].pokdlogA, pubs[i][j].A, i, ctx);
        ret &= verNIZKPoKDLog(pubs[i][j].pokdlogB, pubs[i][j].B, i, ctx);

        // Verify NIZKPoWFCom
        ret &= verNIZKPoWFCom(pubs[i][j].powfcom, pubs[i][j].phi, pubs[i][j].A,
                              pubs[i][j].B, i, ctx);
      }
    }
  }
  return ret;
}

/**
 * @brief In the Round 1 phase, bidders send their public keys and NIZK
 *
 * @param step Current step of the auction, starting from 0
 * @return RoundOnePub
 */
RoundOnePub Bidder::roundOne(size_t step) {
  RoundOnePub pub;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *x = BN_new();
  BIGNUM *r = BN_new();
  EC_POINT *X = EC_POINT_new(group);
  EC_POINT *R = EC_POINT_new(group);

  BN_rand_range(x, order);
  BN_rand_range(r, order);
  EC_POINT_mul(group, X, x, NULL, NULL, ctx);
  EC_POINT_mul(group, R, r, NULL, NULL, ctx);

  keys[step].X = X;
  keys[step].R = R;
  keys[step].x = x;
  keys[step].r = r;

  pub.X = X;
  pub.R = R;

  curInfo[id_].X = X;
  curInfo[id_].R = R;

  // Generate NIZKoKDLog
  genNIZKPoKDLog(pub.pokdlogX, X, x, ctx);
  genNIZKPoKDLog(pub.pokdlogR, R, r, ctx);

  return pub;
}

/**
 * @brief Verify the Round 1 messages of all bidders
 *
 * @param pubs RoundOnePub in order of bidders id, including self
 * @return bool, true if all Round 1 messages are valid and NIZK Proofs is
 * valid, false otherwise
 */
bool Bidder::verifyRoundOne(std::vector<RoundOnePub> pubs) {
  bool ret = true;
  BN_CTX *ctx = BN_CTX_new();
  for (size_t i = 0; i < pubs.size(); ++i) {
    if (i != id_) {
      ret &= verNIZKPoKDLog(pubs[i].pokdlogX, pubs[i].X, i, ctx);
      ret &= verNIZKPoKDLog(pubs[i].pokdlogR, pubs[i].R, i, ctx);
      curInfo[i].X = pubs[i].X;
      curInfo[i].R = pubs[i].R;
    }
  }
  return ret;
}

/**
 * @brief In the Round 2 phase, bidders encode their bid bits
 *
 * @param pubs RoundOnePub in order of bidders id, including self
 * @param step Current step of the auction, starting from 0
 * @return RoundTwoPub
 */
RoundTwoPub Bidder::roundTwo(const std::vector<RoundOnePub> pubs, size_t step) {
  RoundTwoPub pub;
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *b = EC_POINT_new(group); // encoded bit
  EC_POINT *firstHalfSum = EC_POINT_new(group);
  EC_POINT *secondHalfSum = EC_POINT_new(group);

  int bit = binaryBidStr[step] - '0';

  // calaulate Y for each bidder
  for (size_t id = 0; id < n_; ++id) {
    EC_POINT_set_to_infinity(group, firstHalfSum);
    for (size_t i = 0; i < id; ++i) {
      EC_POINT_add(group, firstHalfSum, firstHalfSum, pubs[i].X, ctx);
    }

    EC_POINT_set_to_infinity(group, secondHalfSum);
    for (size_t i = id + 1; i < pubs.size(); ++i) {
      EC_POINT_add(group, secondHalfSum, secondHalfSum, pubs[i].X, ctx);
    }

    EC_POINT_invert(group, secondHalfSum, ctx);
    EC_POINT_add(group, curInfo[id].Y, firstHalfSum, secondHalfSum, ctx);
  }

  if ((!junctionFlag && bit == 0) ||
      (junctionFlag && (bit == 0 || prevDecidingBit == 0))) {
    // PRINT_MESSAGE("Bidder " << id_ << " encodes bit 0 in step " << step)
    EC_POINT_mul(group, b, NULL, curInfo[id_].Y, keys[step].x, ctx);
  } else { // (!junctionFlag && bit == 1) || (junctionFlag && bit == 1 &&
           // prevDecidingBit == 1))
    // PRINT_MESSAGE("Bidder " << id_ << " encodes bit 1 in step " << step)
    EC_POINT_mul(group, b, NULL, keys[step].R, keys[step].x, ctx);
  }

  pub.b = b;
  curInfo[id_].b = b;

  if (!junctionFlag) {
    // Generate NIZKPoWFStage1
    pub.stage = STAGE1;
    genNIZKPoWFStage1(pub.powf.powfstage1, b, keys[step].X, curInfo[id_].Y,
                      keys[step].R, commitments[step].phi, commitments[step].A,
                      commitments[step].B, keys[step].x,
                      commitments[step].alpha, bit, ctx);
  } else {
    // Generate NIZKPoWFStage2
    pub.stage = STAGE2;
    genNIZKPoWFStage2(pub.powf.powfstage2, b, keys[step].X, keys[step].R,
                      prevDecidingInfo[id_].b, keys[prevDecidingStep].X,
                      keys[prevDecidingStep].R, commitments[step].phi,
                      commitments[step].A, commitments[step].B, curInfo[id_].Y,
                      prevDecidingInfo[id_].Y, keys[step].x,
                      keys[prevDecidingStep].x, commitments[step].alpha, bit,
                      prevDecidingBit, ctx);
  }

  return pub;
}

/**
 * @brief Verify the Round 2 messages of all bidders
 *
 * @param pubs RoundTwoPub in order of bidders id, including self
 * @param step Current step of the auction, starting from 0
 * @return bool, true if all Round 2 messages are valid and NIZK Proofs is
 * valid, false otherwise
 */
bool Bidder::verifyRoundTwo(std::vector<RoundTwoPub> pubs, size_t step) {
  bool ret = true;
  BN_CTX *ctx = BN_CTX_new();

  for (size_t i = 0; i < pubs.size(); ++i) {
    if (i != id_) {
      curInfo[i].b = pubs[i].b;

      if (!junctionFlag) {
        assert(pubs[i].stage == STAGE1);
        ret &= verNIZKPoWFStage1(
            pubs[i].powf.powfstage1, curInfo[i].b, curInfo[i].X, curInfo[i].Y,
            curInfo[i].R, commitmentsBB[i][step].phi, commitmentsBB[i][step].A,
            commitmentsBB[i][step].B, i, ctx);
      } else {
        assert(pubs[i].stage == STAGE2);
        ret &= verNIZKPoWFStage2(
            pubs[i].powf.powfstage2, curInfo[i].b, curInfo[i].X, curInfo[i].R,
            prevDecidingInfo[i].b, prevDecidingInfo[i].X, prevDecidingInfo[i].R,
            commitmentsBB[i][step].phi, commitmentsBB[i][step].A,
            commitmentsBB[i][step].B, curInfo[i].Y, prevDecidingInfo[i].Y, i,
            ctx);
      }
    }
  }

  return ret;
}

/**
 * @brief In the Round 3 phase, bidders send their encoded bid bits
 *
 * @param pubs RoundTwoPub in order of bidders id, including self
 * @param step Current step of the auction, starting from 0
 * @return size_t, 1 if winning bidder encodes bit 1 in this step, 0 otherwise
 */
size_t Bidder::roundThree(const std::vector<RoundTwoPub> pubs, size_t step) {
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *sum = EC_POINT_new(group);

  for (size_t i = 0; i < pubs.size(); ++i) {
    EC_POINT_add(group, sum, sum, pubs[i].b, ctx);
  }

  if (!EC_POINT_is_at_infinity(group, sum)) {
    // exist bidder encodes bit 1 in this step, i.e. this step is *deciding
    // step*
    junctionFlag = true;
    prevDecidingStep = step;
    prevDecidingBit &= (binaryBidStr[step] - '0');
    maxBid |= (1 << (c_ - step - 1));

    // prevDecidingInfo = curInfo
    for (size_t i = 0; i < n_; ++i) {
      prevDecidingInfo[i].X = curInfo[i].X;
      prevDecidingInfo[i].R = curInfo[i].R;
      prevDecidingInfo[i].Y = curInfo[i].Y;
      prevDecidingInfo[i].b = curInfo[i].b;
    }

    return 1;
  }

  return 0;
}
