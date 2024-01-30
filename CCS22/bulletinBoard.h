#ifndef BULLETIN_BOARD_H
#define BULLETIN_BOARD_H

#include "params.h"
#include "print.h"
#include "types.h"
#include <iostream>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string>
#include <vector>

class BulletinBoard {
public:
  BulletinBoard(size_t, size_t);

  const PubParams &getPubParams() const;
  void addCommitmentMsg(size_t, const EC_POINT *);
  void addPublicKeyMsg(size_t, const std::vector<EC_POINT *> &);
  const std::vector<EC_POINT *> getPublicKeysByStep(size_t) const;

private:
  size_t n_;
  size_t c_;

  // public parameters
  const EC_GROUP *group_;
  const BIGNUM *order_;
  const EC_POINT *g_;
  const EC_POINT *g1_;
  const EC_POINT *h_;
  const PubParams pubParams_;

  std::vector<const EC_POINT *> commitments_;
  std::vector<std::vector<EC_POINT *>> pubKeys_;
};

#endif // BULLETIN_BOARD_H
