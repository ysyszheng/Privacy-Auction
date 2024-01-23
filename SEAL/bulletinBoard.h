#ifndef BULLETIN_BOARD_H
#define BULLETIN_BOARD_H

#include "params.h"
#include "types.h"
#include <iostream>
#include <memory>
#include <string>
#include <vector>

// FIXME: use memcopy?
class BulletinBoard {
public:
  BulletinBoard(size_t, size_t);
  ~BulletinBoard();

  void addCommitmentMsg(const CommitmentPub &, size_t);
  void addRoundOneMsg(const RoundOnePub&, size_t);
  void addRoundTwoMsg(const RoundTwoPub&, size_t);

  const std::vector<CommitmentPub> &getCommitments() const;
  const std::vector<RoundOnePub> &getRoundOnePubs() const;
  const std::vector<RoundTwoPub> &getRoundTwoPubs() const;

private:
  size_t n_;
  size_t c_;

  std::vector<CommitmentPub> commitments_;
  std::vector<RoundOnePub> roundOnePubs_;
  std::vector<RoundTwoPub> roundTwoPubs_;
};

#endif // BULLETIN_BOARD_H
