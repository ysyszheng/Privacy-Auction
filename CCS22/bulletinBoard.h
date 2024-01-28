#ifndef BULLETIN_BOARD_H
#define BULLETIN_BOARD_H

#include "params.h"
#include "print.h"
#include <iostream>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string>
#include <vector>

class BulletinBoard {
public:
  BulletinBoard(size_t, size_t);
  ~BulletinBoard();

private:
  size_t n_;
  size_t c_;

  // public parameters
  std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group_;
  std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> g_;
  std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> g1_;
  std::unique_ptr<BIGNUM, decltype(&BN_free)> order_;
};

#endif // BULLETIN_BOARD_H
