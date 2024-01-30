#ifndef BIDDER_H
#define BIDDER_H

#include "bulletinBoard.h"
#include "params.h"
#include "print.h"
#include "types.h"
#include <cstddef>
#include <iostream>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string>
#include <vector>

class Bidder {
public:
  Bidder(size_t, size_t, size_t, const PubParams &);

  size_t getId();
  size_t getBid();
  size_t getMaxBid();

  void setup();
  const EC_POINT *getCommitments() const;
  const std::vector<EC_POINT *> &getPubKeys() const;

  void BESEncode(const std::vector<EC_POINT *> &, size_t);
  const OT_S *OTSend(size_t, const OT_R1 &);
  void enterDeciderRound(size_t);

protected:
  typedef struct {
    BIGNUM *x;
    BIGNUM *r;
    BIGNUM *randomness; // gamma in common bidders, beta in evaluator
  } PrivKey;

  std::vector<PrivKey *> privKeys;

  size_t id_;
  size_t bid_;
  size_t c_;
  size_t n_;

  std::vector<EC_POINT *> pubKeys;

  const EC_GROUP *group;
  const EC_POINT *g;
  const EC_POINT *g1;
  const EC_POINT *h;
  const BIGNUM *order;

  const BIGNUM *R;
  BIGNUM *H;
  EC_POINT *Com;
  EC_POINT *B;

  bool inRaceFlag;
  size_t d;
  size_t maxBid;
  std::string binaryBidStr;
};

#endif // BIDDER_H
