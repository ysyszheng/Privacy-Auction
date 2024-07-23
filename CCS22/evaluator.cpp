#include "evaluator.h"
#include "bidder.h"
#include "dataTracker.h"
#include "hash.h"
#include "print.h"
#include "timeTracker.h"
#include "types.h"
#include <cassert>
#include <cstddef>
#include <openssl/bn.h>
#include <openssl/ec.h>

Evaluator::Evaluator(size_t id, size_t n, size_t c, const PubParams &pubParams)
    : Bidder(id, n, c, pubParams), Bs(n) {}

void Evaluator::setup() {
  TimeTracker::getInstance().start(EVALUATOR_CATEGORY);
  setupInner();
  TimeTracker::getInstance().stop(EVALUATOR_CATEGORY);
}

void Evaluator::BESEncode(const std::vector<EC_POINT *> &BBpubKeys,
                          size_t step) {
  TimeTracker::getInstance().start(EVALUATOR_CATEGORY);
  BESEncodeInner(BBpubKeys, step);
  TimeTracker::getInstance().stop(EVALUATOR_CATEGORY);
}

const OT_R1 &Evaluator::OTReceive1(size_t step) {
  // FIXME: For convenience, let T1=g1. This does not
  // affect testing, but may affect security
  TimeTracker::getInstance().start(EVALUATOR_CATEGORY);

  BIGNUM *alpha = BN_new();
  BIGNUM *k = BN_new();
  EC_POINT *G = EC_POINT_new(group);
  EC_POINT *H = EC_POINT_new(group);
  EC_POINT *T1 = EC_POINT_new(group);
  EC_POINT *T2 = EC_POINT_new(group);
  EC_POINT *tmp = EC_POINT_new(group);
  BN_CTX *ctx = BN_CTX_new();
  OT_R1 *ot_r1 = new OT_R1();

  BN_set_word(alpha, d); // alpha_j=d_{ej}

  BN_rand(k, 256, -1, 0);
  EC_POINT_mul(group, T1, k, NULL, NULL, ctx);
  BN_rand(k, 256, -1, 0);
  EC_POINT_mul(group, T2, k, NULL, NULL, ctx);

  // G = g^beta * T1^alpha, H = h^beta * T2^alpha
  EC_POINT_mul(group, G, privKeys[step]->randomness, T1, alpha, ctx);
  EC_POINT_mul(group, H, NULL, T2, alpha, ctx);
  EC_POINT_mul(group, tmp, NULL, h, privKeys[step]->randomness, ctx);
  EC_POINT_add(group, H, H, tmp, ctx);

  ot_r1->T1 = T1;
  ot_r1->T2 = T2;
  ot_r1->G = G;
  ot_r1->H = H;

  TimeTracker::getInstance().stop(EVALUATOR_CATEGORY);
  return *ot_r1;
}

size_t Evaluator::OTReceive2(size_t step,
                             const std::vector<const OT_S *> &ots) {
  TimeTracker::getInstance().start(EVALUATOR_CATEGORY);

  if (d == 1) {
    maxBid |= (1 << (c_ - step - 1));

    TimeTracker::getInstance().stop(EVALUATOR_CATEGORY);
    return 1;
  } else { // d == 0
    EC_POINT *sum = EC_POINT_new(group);
    EC_POINT *M0 = EC_POINT_new(group);
    EC_POINT *z = EC_POINT_new(group);
    BN_CTX *ctx = BN_CTX_new();

    EC_POINT_set_to_infinity(group, sum);

    assert(ots.size() == n_ - 1);
    for (size_t i = 0; i < n_ - 1; ++i) {
      assert(ots[i] != nullptr);
      EC_POINT_copy(z, ots[i]->z);
      EC_POINT_invert(group, z, ctx);
      EC_POINT_mul(group, z, NULL, z, privKeys[step]->randomness, ctx);
      EC_POINT_add(group, M0, ots[i]->C0, z, ctx); // M0 = C0 * z^{-beta}
      EC_POINT_add(group, sum, sum, M0, ctx);
    }
    EC_POINT_add(group, sum, sum, B, ctx);

    if (!EC_POINT_is_at_infinity(group, sum)) {
      inRaceFlag = false;
      maxBid |= (1 << (c_ - step - 1));

      TimeTracker::getInstance().stop(EVALUATOR_CATEGORY);
      return 1;
    } else {
      TimeTracker::getInstance().stop(EVALUATOR_CATEGORY);
      return 0;
    }
  }
}
