#ifndef BIDDER_H
#define BIDDER_H

#include "params.h"
#include <iostream>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string>
#include <vector>
#include "print.h"

class Bidder {
public:
  Bidder(size_t, size_t, size_t);

  size_t getId();
  size_t getBid();
  size_t getMaxBid();

private:
  size_t id_;
  size_t bid_;
  size_t c_;
  size_t n_;

  const EC_GROUP *group;
  const EC_POINT *generator;
  const BIGNUM *order;

  size_t maxBid;
  std::string binaryBidStr;
};

#endif // BIDDER_H
