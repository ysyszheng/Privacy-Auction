#include "evaluator.h"
#include "bidder.h"
#include "hash.h"
#include "types.h"
#include <cassert>
#include <cstddef>
#include <openssl/bn.h>
#include <openssl/ec.h>

void Evaluator::setup() {
  size_t array_len = 3 * c_;
  const BIGNUM *bns[array_len];
  BIGNUM *H = BN_new();
  BIGNUM *bnBid = BN_new();
  EC_POINT *tmp = EC_POINT_new(group);
  BN_CTX *ctx = BN_CTX_new();

  // generate private keys
  for (size_t i = 0; i < c_; i++) {
    BIGNUM *x = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *beta = BN_new();
    EC_POINT *X = EC_POINT_new(group);

    BN_rand_range(x, order);
    BN_rand_range(r, order);
    BN_rand_range(beta, order);
    EC_POINT_mul(group, X, x, NULL, NULL, ctx);

    privKeys[i] = {x, r, beta};
    pubKeys[i] = X;
    bns[i] = x;
    bns[c_ + i] = r;
    bns[2 * c_ + i] = beta;
  }

  // generate hash
  SHA256inSetup(H, order, bns, array_len, ctx);

  // generate commitment, Com = g^b * g1^H * h^R
  Com = EC_POINT_new(group);
  BN_set_word(bnBid, bid_);
  EC_POINT_mul(group, Com, bnBid, g1, H, ctx);
  EC_POINT_mul(group, tmp, NULL, h, R, ctx);
  EC_POINT_add(group, Com, Com, tmp, ctx);
}

const OT_R1 *Evaluator::OTReceive1(size_t step) {
  BIGNUM *alpha = BN_new();
  BIGNUM *k = BN_new();
  EC_POINT *G = EC_POINT_new(group);
  EC_POINT *H = EC_POINT_new(group);
  EC_POINT *T1 = EC_POINT_new(group);
  EC_POINT *T2 = EC_POINT_new(group);
  EC_POINT *tmp = EC_POINT_new(group);
  BN_CTX *ctx = BN_CTX_new();
  OT_R1 *ot_r1 = new OT_R1();

  BN_set_word(alpha, d);

  BN_rand(k, 256, -1, 0);
  EC_POINT_mul(group, T1, k, NULL, NULL, ctx);
  BN_rand(k, 256, -1, 0);
  EC_POINT_mul(group, T2, k, NULL, NULL, ctx);

  // G = g^beta * T1^alpha, H = h^beta * T2^alpha
  EC_POINT_mul(group, G, privKeys[step].beta, T1, alpha, ctx);
  EC_POINT_mul(group, H, NULL, T2, alpha, ctx);
  EC_POINT_mul(group, tmp, privKeys[step].beta, NULL, NULL, ctx);
  EC_POINT_add(group, G, G, tmp, ctx);

  ot_r1->T1 = T1;
  ot_r1->T2 = T2;
  ot_r1->G = G;
  ot_r1->H = H;

  return ot_r1;
}

size_t Evaluator::OTReceive2(size_t step,
                             const std::vector<const OT_S *> &ots) {
  if (d == 1) {
    return 1;
  } else { // d == 0
    EC_POINT *sum = EC_POINT_new(group);
    EC_POINT *M0 = EC_POINT_new(group);
    EC_POINT *z = EC_POINT_new(group);
    BN_CTX *ctx = BN_CTX_new();

    EC_POINT_set_to_infinity(group, sum);

    assert(ots.size() == n_ - 1);
    for (size_t i = 0; i < n_; ++i) {
      if (i != id_) {
        EC_POINT_copy(z, ots[i]->z);
        EC_POINT_invert(group, z, ctx);
        EC_POINT_mul(group, z, NULL, z, privKeys[step].beta, ctx);
        EC_POINT_add(group, M0, ots[i]->C0, z, ctx); // M0 = C0 * z^{-beta}
        EC_POINT_add(group, sum, sum, M0, ctx);
      } else { // i==id_
        EC_POINT_add(group, sum, sum, B, ctx);
      }
    }

    if (!EC_POINT_is_at_infinity(group, sum)) {
      inRaceFlag = false;
      return 1;
    } else {
      return 0;
    }
  }
}
