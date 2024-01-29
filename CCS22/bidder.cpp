#include "bidder.h"
#include "hash.h"
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
      inRaceFlag(true), maxBid(0) {
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

void Bidder::setup() {
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

    privKeys[i] = {x, r, gamma};
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

EC_POINT *Bidder::BESEncode(std::vector<EC_POINT *> &BBpubKeys, size_t step) {
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *Y = EC_POINT_new(group);
  EC_POINT *firstHalfSum = EC_POINT_new(group);
  EC_POINT *secondHalfSum = EC_POINT_new(group);

  int bit = binaryBidStr[step] - '0';
  d = inRaceFlag && bit == 1 ? 1 : 0;

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
    // PRINT_MESSAGE("Bidder " << id_ << " encodes bit 0 in step " << step)
    EC_POINT_mul(group, B, NULL, Y, privKeys[step].x, ctx);
    bit = 0;
  } else { // d == 1
    // PRINT_MESSAGE("Bidder " << id_ << " encodes bit 1 in step " << step)
    EC_POINT_mul(group, B, privKeys[step].r, NULL, NULL, ctx);
    bit = 1;
  }

  return B;
}

const OT_S &Bidder::OTSend(const OT_R1 &otr1) {
  auto OTR1 = []() {};
}

