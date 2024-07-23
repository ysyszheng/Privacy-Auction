#ifndef BULLETIN_BOARD_H
#define BULLETIN_BOARD_H

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

class BulletinBoard {
public:
  BulletinBoard(size_t, size_t);

  const PubParams &getPubParams() const;
  void addCommitmentMsg(size_t, const EC_POINT *);
  void addPublicKeyMsg(size_t, const std::vector<EC_POINT *> &);
  const std::vector<EC_POINT *> getPublicKeysByStep(size_t) const;

  void addOTR1Vec(OT_R1_VEC);
  OT_R1 getOTR1(size_t) const;
  void addOTS(size_t, const OT_S*);
  OT_S_VEC getOTSVec() const;

  void addd(size_t);
  size_t getd() const;

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
  OT_R1_VEC ot_r1_vec_;
  OT_S_VEC ot_s_vec_;

  size_t d_;

  size_t track_ec_group_size(const std::string &, const EC_GROUP *) const;
  size_t track_ec_point_size(const std::string &, const EC_POINT *) const;
  size_t track_bignum_size(const std::string &, const BIGNUM *) const;
};

#endif // BULLETIN_BOARD_H
