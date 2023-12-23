#ifndef BIDDER_H
#define BIDDER_H

#include "params.h"
#include "types.h"
#include <cassert>
#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <cstddef>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <random>
#include <string>
#include <vector>

class Bidder {
public:
  Bidder(size_t, size_t);

  size_t getId();
  size_t getBid();
  size_t getMaxBid();

  CommitmentPub commitBid();
  RoundOnePub roundOne(size_t);
  RoundTwoPub roundTwo(const std::vector<RoundOnePub>, size_t);
  size_t roundThree(const std::vector<RoundTwoPub>, size_t);

  int verifyCommitment(std::vector<CommitmentPub>);
  int verifyRoundOne(std::vector<RoundOnePub>, size_t);
  int verifyRoundTwo(std::vector<RoundTwoPub>, size_t);

private:
  struct Commitment {
    EC_POINT *phi;
    EC_POINT *A;
    EC_POINT *B;
    BIGNUM *alpha;
    BIGNUM *beta;
  };

  struct Key {
    EC_POINT *X;
    EC_POINT *R;
    BIGNUM *x;
    BIGNUM *r;
  };

  size_t id_;
  size_t bid_;
  size_t c_;

  size_t maxBid;
  std::string binaryBidStr;
  bool junctionFlag; // whether reached junction
  size_t prevDecidingStep;
  size_t prevDecidingBit; // bit d in paper

  EC_GROUP *group;
  const EC_POINT *generator;
  const BIGNUM *order;

  std::vector<Commitment> commitments;
  std::vector<Key> keys;
};

#endif /* BIDDER_H */
