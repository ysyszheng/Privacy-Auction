#include "bulletinBoard.h"
#include "dataTracker.h"
#include "print.h"
#include <openssl/err.h>

BulletinBoard::BulletinBoard(size_t n, size_t c) : n_(n), c_(c) {
  commitments_.resize(n_);
  roundOnePubs_.resize(n_);
  roundTwoPubs_.resize(n_);

  for (size_t i = 0; i < n_; ++i) {
    commitments_[i].resize(c_);
  }

  if (NULL == (group = EC_GROUP_new_by_curve_name(CURVE))) {
    ERR_print_errors_fp(stderr);
  }
}

BulletinBoard::~BulletinBoard() {}

void BulletinBoard::addCommitmentMsg(const CommitmentPub &commitment,
                                     size_t id) {
  commitments_[id] = commitment;

#ifdef ENABLE_COMMUNICATION_TRACKING
  DataTracker::getInstance().addData(sizeof(id));

  for (auto &c : commitment) {
    track_ec_point_size(c.phi);
    track_ec_point_size(c.A);
    track_ec_point_size(c.B);

    track_ec_point_size(c.pokdlogA.eps);
    track_bignum_size(c.pokdlogA.rho);

    track_ec_point_size(c.pokdlogB.eps);
    track_bignum_size(c.pokdlogB.rho);

    track_ec_point_size(c.powfcom.eps11);
    track_ec_point_size(c.powfcom.eps12);
    track_ec_point_size(c.powfcom.eps21);
    track_ec_point_size(c.powfcom.eps22);
    track_bignum_size(c.powfcom.rho1);
    track_bignum_size(c.powfcom.rho2);
    track_bignum_size(c.powfcom.ch2);
  }
#endif
}

void BulletinBoard::addRoundOneMsg(const RoundOnePub &roundOnePub, size_t id) {
  roundOnePubs_[id] = roundOnePub;

#ifdef ENABLE_COMMUNICATION_TRACKING
  DataTracker::getInstance().addData(sizeof(id));

  track_ec_point_size(roundOnePub.X);
  track_ec_point_size(roundOnePub.R);

  track_ec_point_size(roundOnePub.pokdlogX.eps);
  track_bignum_size(roundOnePub.pokdlogX.rho);

  track_ec_point_size(roundOnePub.pokdlogR.eps);
  track_bignum_size(roundOnePub.pokdlogR.rho);
#endif
}

void BulletinBoard::addRoundTwoMsg(const RoundTwoPub &roundTwoPub, size_t id) {
  roundTwoPubs_[id] = roundTwoPub;

#ifdef ENABLE_COMMUNICATION_TRACKING
  DataTracker::getInstance().addData(sizeof(id));
  DataTracker::getInstance().addData(sizeof(roundTwoPub.stage));

  track_ec_point_size(roundTwoPub.b);

  if (roundTwoPub.stage == STAGE1) {
    track_ec_point_size(roundTwoPub.powf.powfstage1.eps11);
    track_ec_point_size(roundTwoPub.powf.powfstage1.eps12);
    track_ec_point_size(roundTwoPub.powf.powfstage1.eps13);
    track_ec_point_size(roundTwoPub.powf.powfstage1.eps14);
    track_ec_point_size(roundTwoPub.powf.powfstage1.eps21);
    track_ec_point_size(roundTwoPub.powf.powfstage1.eps22);
    track_ec_point_size(roundTwoPub.powf.powfstage1.eps23);
    track_ec_point_size(roundTwoPub.powf.powfstage1.eps24);

    track_bignum_size(roundTwoPub.powf.powfstage1.rho11);
    track_bignum_size(roundTwoPub.powf.powfstage1.rho12);
    track_bignum_size(roundTwoPub.powf.powfstage1.rho21);
    track_bignum_size(roundTwoPub.powf.powfstage1.rho22);

    track_bignum_size(roundTwoPub.powf.powfstage1.ch2);
  } else {
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps11);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps12);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps13);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps11prime);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps12prime);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps13prime);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps21);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps22);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps23);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps21prime);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps22prime);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps23prime);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps31);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps32);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps31prime);
    track_ec_point_size(roundTwoPub.powf.powfstage2.eps32prime);

    track_bignum_size(roundTwoPub.powf.powfstage2.rho11);
    track_bignum_size(roundTwoPub.powf.powfstage2.rho12);
    track_bignum_size(roundTwoPub.powf.powfstage2.rho13);
    track_bignum_size(roundTwoPub.powf.powfstage2.rho21);
    track_bignum_size(roundTwoPub.powf.powfstage2.rho22);
    track_bignum_size(roundTwoPub.powf.powfstage2.rho23);
    track_bignum_size(roundTwoPub.powf.powfstage2.rho31);
    track_bignum_size(roundTwoPub.powf.powfstage2.rho32);

    track_bignum_size(roundTwoPub.powf.powfstage2.ch2);
    track_bignum_size(roundTwoPub.powf.powfstage2.ch3);
  }
#endif
}

const std::vector<const EC_POINT *> BulletinBoard::getRoundOneXs() const {
  std::vector<const EC_POINT *> Xs;
  Xs.reserve(roundOnePubs_.size());

  for (auto &roundOnePub : roundOnePubs_) {
    Xs.push_back(roundOnePub.X);
#ifdef ENABLE_COMMUNICATION_TRACKING
    track_ec_point_size(roundOnePub.X);
#endif
  }

  return Xs;
}

const std::vector<const EC_POINT *> BulletinBoard::getRoundTwoBs() const {
  std::vector<const EC_POINT *> Bs;
  Bs.reserve(roundTwoPubs_.size());

  for (auto &roundTwoPub : roundTwoPubs_) {
    Bs.push_back(roundTwoPub.b);
#ifdef ENABLE_COMMUNICATION_TRACKING
    track_ec_point_size(roundTwoPub.b);
#endif
  }

  return Bs;
}

const std::vector<CommitmentPub> &BulletinBoard::getCommitments() const {
#ifdef ENABLE_COMMUNICATION_TRACKING
  for (auto &commitment : commitments_) {
    for (auto &c : commitment) {
      track_ec_point_size(c.phi);
      track_ec_point_size(c.A);
      track_ec_point_size(c.B);

      track_ec_point_size(c.pokdlogA.eps);
      track_bignum_size(c.pokdlogA.rho);

      track_ec_point_size(c.pokdlogB.eps);
      track_bignum_size(c.pokdlogB.rho);

      track_ec_point_size(c.powfcom.eps11);
      track_ec_point_size(c.powfcom.eps12);
      track_ec_point_size(c.powfcom.eps21);
      track_ec_point_size(c.powfcom.eps22);
      track_bignum_size(c.powfcom.rho1);
      track_bignum_size(c.powfcom.rho2);
      track_bignum_size(c.powfcom.ch2);
    }
  }
#endif

  return commitments_;
}

const std::vector<RoundOnePub> &BulletinBoard::getRoundOnePubs() const {
#ifdef ENABLE_COMMUNICATION_TRACKING
  for (auto &roundOnePub : roundOnePubs_) {
    track_ec_point_size(roundOnePub.X);
    track_ec_point_size(roundOnePub.R);

    track_ec_point_size(roundOnePub.pokdlogX.eps);
    track_bignum_size(roundOnePub.pokdlogX.rho);

    track_ec_point_size(roundOnePub.pokdlogR.eps);
    track_bignum_size(roundOnePub.pokdlogR.rho);
  }
#endif

  return roundOnePubs_;
}

const std::vector<RoundTwoPub> &BulletinBoard::getRoundTwoPubs() const {
#ifdef ENABLE_COMMUNICATION_TRACKING
  for (auto &roundTwoPub : roundTwoPubs_) {
    track_ec_point_size(roundTwoPub.b);

    if (roundTwoPub.stage == STAGE1) {
      track_ec_point_size(roundTwoPub.powf.powfstage1.eps11);
      track_ec_point_size(roundTwoPub.powf.powfstage1.eps12);
      track_ec_point_size(roundTwoPub.powf.powfstage1.eps13);
      track_ec_point_size(roundTwoPub.powf.powfstage1.eps14);
      track_ec_point_size(roundTwoPub.powf.powfstage1.eps21);
      track_ec_point_size(roundTwoPub.powf.powfstage1.eps22);
      track_ec_point_size(roundTwoPub.powf.powfstage1.eps23);
      track_ec_point_size(roundTwoPub.powf.powfstage1.eps24);

      track_bignum_size(roundTwoPub.powf.powfstage1.rho11);
      track_bignum_size(roundTwoPub.powf.powfstage1.rho12);
      track_bignum_size(roundTwoPub.powf.powfstage1.rho21);
      track_bignum_size(roundTwoPub.powf.powfstage1.rho22);

      track_bignum_size(roundTwoPub.powf.powfstage1.ch2);
    } else {
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps11);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps12);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps13);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps11prime);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps12prime);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps13prime);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps21);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps22);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps23);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps21prime);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps22prime);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps23prime);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps31);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps32);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps31prime);
      track_ec_point_size(roundTwoPub.powf.powfstage2.eps32prime);

      track_bignum_size(roundTwoPub.powf.powfstage2.rho11);
      track_bignum_size(roundTwoPub.powf.powfstage2.rho12);
      track_bignum_size(roundTwoPub.powf.powfstage2.rho13);
      track_bignum_size(roundTwoPub.powf.powfstage2.rho21);
      track_bignum_size(roundTwoPub.powf.powfstage2.rho22);
      track_bignum_size(roundTwoPub.powf.powfstage2.rho23);
      track_bignum_size(roundTwoPub.powf.powfstage2.rho31);
      track_bignum_size(roundTwoPub.powf.powfstage2.rho32);

      track_bignum_size(roundTwoPub.powf.powfstage2.ch2);
      track_bignum_size(roundTwoPub.powf.powfstage2.ch3);
    }
  }
#endif

  return roundTwoPubs_;
}

size_t BulletinBoard::track_ec_point_size(const EC_POINT *point) const {
  // size_t len = EC_POINT_point2buf(group, point,
  // POINT_CONVERSION_UNCOMPRESSED,
  //                                 NULL, NULL);
  size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                  NULL, 0, NULL);
  DataTracker::getInstance().addData(len);
  return len;
}

size_t BulletinBoard::track_bignum_size(const BIGNUM *bn) const {
  size_t len = BN_num_bytes(bn);
  DataTracker::getInstance().addData(len);
  return len;
}
