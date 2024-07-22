#ifndef BULLETIN_BOARD_H
#define BULLETIN_BOARD_H

#include "dataTracker.h"
#include "params.h"
#include "types.h"
#include <iostream>
#include <memory>
#include <openssl/ec.h>
#include <string>
#include <vector>

// FIXME: use memcopy?
class BulletinBoard {
public:
  BulletinBoard(size_t, size_t);
  ~BulletinBoard();

  void addCommitmentMsg(const CommitmentPub &, size_t);
  void addRoundOneMsg(const RoundOnePub &, size_t);
  void addRoundTwoMsg(const RoundTwoPub &, size_t);

  const std::vector<const EC_POINT *> getRoundOneXs() const;
  const std::vector<const EC_POINT *> getRoundTwoBs() const;
  
  const std::vector<CommitmentPub> &getCommitments() const;
  const std::vector<RoundOnePub> &getRoundOnePubs() const;
  const std::vector<RoundTwoPub> &getRoundTwoPubs() const;

private:
  size_t n_;
  size_t c_;

  const EC_GROUP *group;

  std::vector<CommitmentPub> commitments_;
  std::vector<RoundOnePub> roundOnePubs_;
  std::vector<RoundTwoPub> roundTwoPubs_;

  size_t track_ec_point_size(const EC_POINT *) const;
  size_t track_bignum_size(const BIGNUM *) const;
};

#endif // BULLETIN_BOARD_H
