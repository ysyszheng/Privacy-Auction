#include "bulletinBoard.h"
#include "dataTracker.h"
#include "params.h"
#include <cassert>
#include <cstddef>
#include <openssl/bn.h>
#include <openssl/ec.h>

BulletinBoard::BulletinBoard(size_t n, size_t c)
    : n_(n), c_(c), group_(EC_GROUP_new_by_curve_name(CURVE)), order_([this]() {
        BIGNUM *raw_order = BN_new();
        if (raw_order == nullptr ||
            EC_GROUP_get_order(group_, raw_order, nullptr) != 1) {
          PRINT_ERROR("Failed to get order of `raw_group`");
        }
        return raw_order;
      }()),
      g_([this]() {
        const EC_POINT *raw_g = EC_GROUP_get0_generator(group_);
        EC_POINT *g_copy = EC_POINT_dup(raw_g, group_);
        if (g_copy == nullptr) {
          PRINT_ERROR("Failed to copy `raw_g`");
        }
        return g_copy;
      }()),
      g1_([this]() {
        EC_POINT *g1 = EC_POINT_new(group_);
        BIGNUM *bn = BN_new();
        BN_rand(bn, 256, -1, 0);
        if (g1 == nullptr ||
            EC_POINT_mul(group_, g1, bn, nullptr, nullptr, nullptr) != 1) {
          PRINT_ERROR("Failed to compute `g1`");
        }
        return g1;
      }()),
      h_([this]() {
        EC_POINT *h = EC_POINT_new(group_);
        BIGNUM *bn = BN_new();
        BN_rand(bn, 256, -1, 0);
        if (h == nullptr ||
            EC_POINT_mul(group_, h, bn, nullptr, nullptr, nullptr) != 1) {
          PRINT_ERROR("Failed to compute `g1`");
        }
        return h;
      }()),
      pubParams_({group_, g_, g1_, h_, order_}), commitments_(n) {
  assert(c <= C_MAX);

  pubKeys_.resize(n);
  for (size_t i = 0; i < n; i++) {
    pubKeys_[i].resize(c);
  }
}

const PubParams &BulletinBoard::getPubParams() const { return pubParams_; }

void BulletinBoard::addCommitmentMsg(size_t id, const EC_POINT *com) {
  assert(id < n_);
  commitments_[id] = com;
}

void BulletinBoard::addPublicKeyMsg(size_t id,
                                    const std::vector<EC_POINT *> &pubKeys) {
  assert(id < n_);
  assert(pubKeys.size() == c_);
  pubKeys_[id] = pubKeys;
}

const std::vector<EC_POINT *>
BulletinBoard::getPublicKeysByStep(size_t step) const {
  assert(step < c_);
  std::vector<EC_POINT *> pubKeys(n_);
  for (size_t i = 0; i < n_; i++) {
    pubKeys[i] = pubKeys_[i][step];
  }
  return pubKeys;
}
