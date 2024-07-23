#include "bidder.h"
#include "dataTracker.h"
#include "hash.h"
#include "params.h"
#include "print.h"
#include "timeTracker.h"
#include "types.h"
#include <cassert>
#include <cstddef>
#include <cstring>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <random>

using namespace std;

Bidder::Bidder(size_t id, size_t n, size_t c, const PubParams &pubParams)
    : privKeys(c), id_(id), c_(c), n_(n), pubKeys(c), group(pubParams.group),
      g(pubParams.g), g1(pubParams.g1), h(pubParams.h), order(pubParams.order),
      R([this]() {
        BIGNUM *R = BN_new();
        if (R == nullptr || BN_rand_range(R, order) != 1) {
          PRINT_ERROR("Failed to generate random number");
        }
        return R;
      }()),
      B(EC_POINT_new(group)), inRaceFlag(true), maxBid(0) {
  assert(c <= C_MAX);

  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<int> dist(0, (1 << c) - 1);
  bid_ = dist(gen);
  binaryBidStr = bitset<C_MAX>(bid_).to_string().substr(C_MAX - c_);

  PRINT_MESSAGE("Construct Bidder: " << id_ << "\nBid: " << bid_
                                     << ", Bid (in binary): " << binaryBidStr);
}

size_t Bidder::getId() { return id_; }

size_t Bidder::getBid() { return bid_; }

size_t Bidder::getMaxBid() { return maxBid; }

void Bidder::setupInner() {
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
    BIGNUM *gamma = BN_new();
    EC_POINT *X = EC_POINT_new(group);

    BN_rand_range(x, order);
    BN_rand_range(r, order);
    BN_rand_range(gamma, order);
    EC_POINT_mul(group, X, x, NULL, NULL, ctx);

    privKeys[i] = new PrivKey{x, r, gamma};
    pubKeys[i] = X;
    bns[i] = x;
    bns[c_ + i] = r;
    bns[2 * c_ + i] = gamma;
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

/**
 * @brief Use `TimeTracker` to wrap the `Inner` function for easy modification
 * during reload
 *
 */
void Bidder::setup() {
  TimeTracker::getInstance().start(BIDDER_CATEGORY);
  setupInner();
  TimeTracker::getInstance().stop(BIDDER_CATEGORY);
}

/**
 * @brief Return the value directly, the time can be ignored, and there is no
 * need to use `TimeTracker` for timing
 *
 * @return const EC_POINT*
 */
const EC_POINT *Bidder::getCommitments() const { return Com; }

/**
 * @brief Return the reference directly, the time can be ignored, and there is
 * no need to use `TimeTracker` for timing
 *
 * @return const std::vector<EC_POINT *>&
 */
const std::vector<EC_POINT *> &Bidder::getPubKeys() const { return pubKeys; }

void Bidder::BESEncodeInner(const std::vector<EC_POINT *> &BBpubKeys,
                            size_t step) {
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *Y = EC_POINT_new(group);
  EC_POINT *firstHalfSum = EC_POINT_new(group);
  EC_POINT *secondHalfSum = EC_POINT_new(group);

  int bit = binaryBidStr[step] - '0';
  d = (inRaceFlag && bit == 1) ? 1 : 0;

  // calaulate Y for each bidder
  EC_POINT_set_to_infinity(group, firstHalfSum);
  for (size_t i = 0; i < id_; ++i) {
    EC_POINT_add(group, firstHalfSum, firstHalfSum, BBpubKeys[i], ctx);
  }

  EC_POINT_set_to_infinity(group, secondHalfSum);
  for (size_t i = id_ + 1; i < n_; ++i) {
    EC_POINT_add(group, secondHalfSum, secondHalfSum, BBpubKeys[i], ctx);
  }

  EC_POINT_invert(group, secondHalfSum, ctx);
  EC_POINT_add(group, Y, firstHalfSum, secondHalfSum, ctx);

  if (d == 0) {
    EC_POINT_mul(group, B, NULL, Y, privKeys[step]->x, ctx);
  } else { // d == 1
    EC_POINT_mul(group, B, privKeys[step]->r, NULL, NULL, ctx);
  }
}

void Bidder::BESEncode(const std::vector<EC_POINT *> &BBpubKeys, size_t step) {
  TimeTracker::getInstance().start(BIDDER_CATEGORY);
  BESEncodeInner(BBpubKeys, step);
  TimeTracker::getInstance().stop(BIDDER_CATEGORY);
}

const OT_S *Bidder::OTSend(size_t step, const OT_R1 &otr1) {
  // FIXME: For convenience, let T1=g1, s=gamma, t=hash(gamma). This does not
  // affect testing, but may affect security
  TimeTracker::getInstance().start(BIDDER_CATEGORY);

  BIGNUM *s = BN_new();
  BIGNUM *t = BN_new();
  BIGNUM *bn = BN_new();
  EC_POINT *z = EC_POINT_new(group);
  EC_POINT *C0 = EC_POINT_new(group);
  EC_POINT *C1 = EC_POINT_new(group);
  EC_POINT *M1 = EC_POINT_new(group);
  EC_POINT *tmp1 = EC_POINT_new(group);
  EC_POINT *tmp2 = EC_POINT_new(group);
  BN_CTX *ctx = BN_CTX_new();
  OT_S *ot_s = new OT_S();

  BN_rand(bn, 256, -1, 0);
  EC_POINT_mul(group, M1, bn, NULL, NULL, ctx);

  BN_rand_range(s, order);
  BN_rand_range(t, order);
  EC_POINT_mul(group, z, s, h, t, ctx); // z = h^t * g^s

  EC_POINT_mul(group, tmp1, NULL, otr1.G, s, ctx);
  EC_POINT_mul(group, C0, NULL, otr1.H, t, ctx);
  EC_POINT_add(group, C0, tmp1, C0, ctx);
  EC_POINT_add(group, C0, C0, B, ctx); // C0 = G^s * H^t * M0 (M0 = B)

  EC_POINT_copy(tmp1, otr1.T1);
  EC_POINT_invert(group, tmp1, ctx); // tmp1 = T1^{-1}
  EC_POINT_copy(tmp2, otr1.T2);
  EC_POINT_invert(group, tmp2, ctx); // tmp2 = T2^{-1}

  EC_POINT_add(group, tmp1, tmp1, otr1.G, ctx);
  EC_POINT_add(group, tmp2, tmp2, otr1.H, ctx);
  EC_POINT_mul(group, tmp1, NULL, tmp1, s, ctx);
  EC_POINT_mul(group, tmp2, NULL, tmp2, t, ctx);
  EC_POINT_add(group, C1, tmp1, tmp2, ctx);
  EC_POINT_add(group, C1, C1, M1, ctx); // C1 = (G/T1)^s * (H/T2)^t * M1

  ot_s->z = z;
  ot_s->C0 = C0;
  ot_s->C1 = C1;

  TimeTracker::getInstance().stop(BIDDER_CATEGORY);
  return ot_s;
}

void Bidder::enterDeciderRound(size_t step) {
  TimeTracker::getInstance().start(BIDDER_CATEGORY);
  inRaceFlag = d == 0 ? false : inRaceFlag;
  maxBid |= (1 << (c_ - step - 1));
  TimeTracker::getInstance().stop(BIDDER_CATEGORY);
}
