#include "bulletinBoard.h"

BulletinBoard::BulletinBoard(size_t n, size_t c) : n_(n), c_(c) {
  commitments_.resize(n_);
  roundOnePubs_.resize(n_);
  roundTwoPubs_.resize(n_);

  for(size_t i = 0; i < n_; ++i) {
    commitments_[i].resize(c_);
  }
}

BulletinBoard::~BulletinBoard() {}

void BulletinBoard::addCommitmentMsg(const CommitmentPub &commitment,
                                     size_t id) {
  commitments_[id] = commitment;
}

void BulletinBoard::addRoundOneMsg(const RoundOnePub &roundOnePub, size_t id) {
  roundOnePubs_[id] = roundOnePub;
}

void BulletinBoard::addRoundTwoMsg(const RoundTwoPub &roundTwoPub, size_t id) {
  roundTwoPubs_[id] = roundTwoPub;
}

const std::vector<CommitmentPub> &BulletinBoard::getCommitments() const {
  return commitments_;
}

const std::vector<RoundOnePub> &BulletinBoard::getRoundOnePubs() const {
  return roundOnePubs_;
}

const std::vector<RoundTwoPub> &BulletinBoard::getRoundTwoPubs() const {
  return roundTwoPubs_;
}
