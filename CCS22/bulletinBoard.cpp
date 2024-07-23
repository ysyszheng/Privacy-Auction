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
        BIGNUM *bn =
            BN_new(); // FIXME: In fact, it is obtained by hashing `g`, but this
                      // does not affect the test, only the decentralization
        BN_rand(bn, 256, -1, 0);
        if (g1 == nullptr || EC_POINT_mul(group_, g1, bn, nullptr, nullptr,
                                          nullptr) != 1) { // g1=g^bn
          PRINT_ERROR("Failed to compute `g1`");
        }
        return g1;
      }()),
      h_([this]() {
        EC_POINT *h = EC_POINT_new(group_);
        BIGNUM *bn =
            BN_new(); // FIXME: In fact, it is obtained by hashing `g`, but this
                      // does not affect the test, only the decentralization
        BN_rand(bn, 256, -1, 0);
        if (h == nullptr || EC_POINT_mul(group_, h, bn, nullptr, nullptr,
                                         nullptr) != 1) { // h=g^bn
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

const PubParams &BulletinBoard::getPubParams() const {
#ifdef ENABLE_COMMUNICATION_TRACKING
  track_ec_group_size(BIDDER_AND_EVALUATOR_CATEGORY, pubParams_.group);

  track_ec_point_size(BIDDER_AND_EVALUATOR_CATEGORY, pubParams_.g);
  track_ec_point_size(BIDDER_AND_EVALUATOR_CATEGORY, pubParams_.g1);
  track_ec_point_size(BIDDER_AND_EVALUATOR_CATEGORY, pubParams_.h);

  track_bignum_size(BIDDER_AND_EVALUATOR_CATEGORY, pubParams_.order);
#endif
  return pubParams_;
}

void BulletinBoard::addCommitmentMsg(size_t id, const EC_POINT *com) {
  assert(id < n_);

#ifdef ENABLE_COMMUNICATION_TRACKING
  DataTracker::getInstance().addData(BIDDER_AND_EVALUATOR_CATEGORY, sizeof(id));

  track_ec_point_size(BIDDER_AND_EVALUATOR_CATEGORY, com);
#endif

  commitments_[id] = com;
}

void BulletinBoard::addPublicKeyMsg(size_t id,
                                    const std::vector<EC_POINT *> &pubKeys) {
  assert(id < n_);
  assert(pubKeys.size() == c_);

#ifdef ENABLE_COMMUNICATION_TRACKING
  DataTracker::getInstance().addData(BIDDER_AND_EVALUATOR_CATEGORY, sizeof(id));

  for (auto pk : pubKeys) {
    track_ec_point_size(BIDDER_AND_EVALUATOR_CATEGORY, pk);
  }
#endif

  pubKeys_[id] = pubKeys;
}

const std::vector<EC_POINT *>
BulletinBoard::getPublicKeysByStep(size_t step) const {
  assert(step < c_);
  std::vector<EC_POINT *> pubKeys(n_);
  for (size_t i = 0; i < n_; i++) {
    pubKeys[i] = pubKeys_[i][step];

#ifdef ENABLE_COMMUNICATION_TRACKING
    track_ec_point_size(BIDDER_AND_EVALUATOR_CATEGORY, pubKeys[i]);
#endif
  }
  return pubKeys;
}

size_t BulletinBoard::track_ec_group_size(const std::string &category,
                                          const EC_GROUP *group) const {
  BIGNUM *p = BN_new();
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();

  if (!EC_GROUP_get_curve(group, p, a, b, NULL)) {
    BN_free(p);
    BN_free(a);
    BN_free(b);
    return 0;
  }

  int p_len = BN_num_bytes(p);
  int a_len = BN_num_bytes(a);
  int b_len = BN_num_bytes(b);

  size_t len = p_len + a_len + b_len + 3 * sizeof(int);

  BN_free(p);
  BN_free(a);
  BN_free(b);

  DataTracker::getInstance().addData(category, len);
  return len;
}

size_t BulletinBoard::track_ec_point_size(const std::string &category,
                                          const EC_POINT *point) const {
  size_t len = EC_POINT_point2oct(group_, point, POINT_CONVERSION_UNCOMPRESSED,
                                  NULL, 0, NULL);
  DataTracker::getInstance().addData(category, len);
  return len;
}

size_t BulletinBoard::track_bignum_size(const std::string &category,
                                        const BIGNUM *bn) const {
  size_t len = BN_num_bytes(bn);
  DataTracker::getInstance().addData(category, len);
  return len;
}
