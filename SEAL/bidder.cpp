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
Bidder::Bidder(size_t id, size_t c)
    : id_(id), c_(c), maxBid(0), junctionFlag(false), prevDecidingBit(1),
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
 * @brief
 *
 * @param proof
 * @param b B in paper
 * @param X
 * @param Y
 * @param R
 * @param c phi, c, or C in paper
 * @param A
 * @param B \bar{B} in paper
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
  size_t len;
  unsigned char *hash_input;
  unsigned char *hash_output;

  BIGNUM *r11 = BN_new(); // or r12, no matter
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

void Bidder::genNIZKPoWFStage2(NIZKPoWFStage2 &, BN_CTX *) {}

bool Bidder::verNIZKPoWFStage2(NIZKPoWFStage2 &, size_t, BN_CTX *) {}

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
  EC_POINT *b = EC_POINT_new(group);
  EC_POINT *Y = EC_POINT_new(group);
  EC_POINT *firstHalfSum = EC_POINT_new(group);
  EC_POINT *secondHalfSum = EC_POINT_new(group);

  int bit = binaryBidStr[step] - '0';

  EC_POINT_set_to_infinity(group, firstHalfSum);
  for (size_t i = 0; i < id_; ++i) {
    EC_POINT_add(group, firstHalfSum, firstHalfSum, pubs[i].X, ctx);
  }

  EC_POINT_set_to_infinity(group, secondHalfSum);
  for (size_t i = id_ + 1; i < pubs.size(); ++i) {
    EC_POINT_add(group, secondHalfSum, secondHalfSum, pubs[i].X, ctx);
  }

  EC_POINT_invert(group, secondHalfSum, ctx);
  EC_POINT_add(group, Y, firstHalfSum, secondHalfSum, ctx);

  if ((!junctionFlag && bit == 0) ||
      (junctionFlag && (bit == 0 || prevDecidingBit == 0))) {
    // PRINT_MESSAGE("Bidder " << id_ << " encodes bit 0 in step " << step)
    EC_POINT_mul(group, b, NULL, Y, keys[step].x, ctx);
  } else { // (!junctionFlag && bit == 1) || (junctionFlag && bit == 1 &&
           // prevDecidingBit == 1))
    // PRINT_MESSAGE("Bidder " << id_ << " encodes bit 1 in step " << step)
    EC_POINT_mul(group, b, NULL, keys[step].R, keys[step].x, ctx);
  }

  pub.b = b;

  if (!junctionFlag) {
    // Generate NIZKPoWFStage1
    pub.stage = STAGE1;

    genNIZKPoWFStage1(pub.powf.powfstage1, b, keys[step].X, Y, keys[step].R,
                      commitments[step].phi, commitments[step].A,
                      commitments[step].B, keys[step].x,
                      commitments[step].alpha, bit, ctx);
  } else {
    // Generate NIZKPoWFStage2
    pub.stage = STAGE2;
    genNIZKPoWFStage2(pub.powf.powfstage2, ctx);
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
  return true;
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
    // exist bidder encodes bit 1 in this step
    junctionFlag = true;
    prevDecidingStep = step;
    prevDecidingBit &= (binaryBidStr[step] - '0');
    maxBid |= (1 << (c_ - step - 1));
    return 1;
  }
  return 0;
}
