#ifndef EVALUATOR_H
#define EVALUATOR_H

#include "bidder.h"
#include "bulletinBoard.h"
#include "params.h"
#include "print.h"
#include "types.h"
#include <cstddef>
#include <iostream>

class Evaluator : public Bidder {
public:
  Evaluator(size_t, size_t, size_t, const PubParams &);

  void setup() override;
  void BESEncode(const std::vector<EC_POINT *> &, size_t) override;

  const OT_S *OTSend(size_t, const OT_R1 &) = delete;
  void checkIfEnterDeciderRound(size_t) = delete;

  const OT_R1_VEC OTReceive1(size_t);
  size_t OTReceive2(size_t, const OT_S_VEC);

private:
  std::vector<std::vector<BIGNUM *>> randomBeta; // randomness in OT
  std::vector<EC_POINT *> Bs;

  void setupInner() override;
};

#endif // EVALUATOR_H