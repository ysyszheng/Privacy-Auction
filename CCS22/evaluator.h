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

  const OT_S *OTSend(size_t, const OT_R1 &) = delete;
  void enterDeciderRound(size_t) = delete;

  const OT_R1 &OTReceive1(size_t);
  size_t OTReceive2(size_t, const std::vector<const OT_S *> &);

private:
  std::vector<EC_POINT *> Bs;
};

#endif // EVALUATOR_H