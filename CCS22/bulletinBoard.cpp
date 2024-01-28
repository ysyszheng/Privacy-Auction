#include "bulletinBoard.h"
#include "params.h"
#include <openssl/ec.h>

BulletinBoard::BulletinBoard(size_t n, size_t c)
    : n_(n), c_(c),
      group_(EC_GROUP_new_by_curve_name(CURVE), &EC_GROUP_free),
      g_(
          [this]() {
            const EC_POINT *raw_g = EC_GROUP_get0_generator(group_.get());
            EC_POINT *g_copy = EC_POINT_dup(raw_g, group_.get());
            if (g_copy == nullptr) {
              PRINT_ERROR("Failed to copy `raw_g`");
            }
            return g_copy;
          }(),
          &EC_POINT_free),
      g1_(
          [this]() {
            EC_POINT *g1 = EC_POINT_new(group_.get());
            BIGNUM *bn = BN_new();
            if (bn == nullptr || BN_rand_range(bn, order_.get()) != 1) {
              PRINT_ERROR("Failed to generate random number");
            }
            if (g1 == nullptr ||
                EC_POINT_mul(group_.get(), g1, nullptr, g_.get(), bn,
                             nullptr) != 1) {
              PRINT_ERROR("Failed to compute `g1`");
            }
            return g1;
          }(),
          &EC_POINT_free),
      order_(
          [this]() {
            BIGNUM *raw_order = BN_new();
            if (raw_order == nullptr ||
                EC_GROUP_get_order(group_.get(), raw_order, nullptr) != 1) {
              PRINT_ERROR("Failed to get order of `raw_group`");
            }
            return raw_order;
          }(),
          &BN_free) {}

BulletinBoard::~BulletinBoard() {
  // nothing to do
}
