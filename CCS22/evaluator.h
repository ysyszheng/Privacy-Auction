#ifndef EVALUATOR_H
#define EVALUATOR_H

#include "bidder.h"
#include "bulletinBoard.h"
#include "params.h"
#include "print.h"
#include "types.h"
#include <iostream>

class Evaluator : public Bidder {
public:
  void setup() override;
  const OT_R1 *OTReceive1(size_t);
  // TODO: const OT_S &OTSend(const OT_R1 &) = delete;
  size_t OTReceive2(size_t, const std::vector<const OT_S *> &);

private:
  typedef struct {
    BIGNUM *x;
    BIGNUM *r;
    BIGNUM *beta;
  } PrivKey;

  std::vector<PrivKey> privKeys;
};

#endif // EVALUATOR_H