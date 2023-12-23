#include "bidder.h"

using namespace std;

/**
 * @brief Construct a new Bidder object, with a c-bit random bid
 *
 * @param id ID of bidder, should start from 0
 * @param c Number of bits in bid
 */
Bidder::Bidder(size_t id, size_t c)
    : id_(id), c_(c), maxBid(0), junctionFlag(false), prevDecidingBit(1),
      commitments(c), keys(c) {
  assert(c <= C_MAX);

  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<int> dist(0, (1 << c) - 1);
  bid_ = dist(gen);
  binaryBidStr = bitset<C_MAX>(bid_).to_string().substr(C_MAX - c_);

  // PRINT_MESSAGE("Construct Bidder: " << id_ << "\nBid: " << bid_
  //                                    << ", Bid (in binary): " <<
  //                                    binaryBidStr);

  if (NULL == (group = EC_GROUP_new_by_curve_name(NID_SECP256K1))) {
    ERR_print_errors_fp(stderr);
  }
  if (NULL == (generator = EC_GROUP_get0_generator(group))) {
    ERR_print_errors_fp(stderr);
  }
  if (NULL == (order = EC_GROUP_get0_order(group))) {
    ERR_print_errors_fp(stderr);
  }
}

/**
 * @brief Returns the ID of the bidder
 *
 * @return size_t
 */
size_t Bidder::getId() { return id_; }

/**
 * @brief Returns the bid of the bidder
 *
 * @return size_t
 */
size_t Bidder::getBid() { return bid_; }

/**
 * @brief Returns the max bid calculated by the bidder during the auction
 *
 * @return size_t
 */
size_t Bidder::getMaxBid() { return maxBid; }

/**
 * @brief In the Commit phase, bidders commit their bids to the public
 * bulletin board, as well as their NIZK
 *
 * @return CommitmentPub, i.e. std::vector<CommitmentPerBit>
 */
CommitmentPub Bidder::commitBid() {
  CommitmentPub pubs(c_);

  for (size_t i = 0; i < c_; ++i) {
    int bit;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bit_value = BN_new();
    BIGNUM *alpha = BN_new();
    BIGNUM *beta = BN_new();
    BIGNUM *alpha_times_beta = BN_new();
    EC_POINT *commitmentPhi = EC_POINT_new(group);
    EC_POINT *commitmentA = EC_POINT_new(group);
    EC_POINT *commitmentB = EC_POINT_new(group);

    bit = binaryBidStr[i] - '0';
    BN_set_word(bit_value, bit);

    BN_rand_range(alpha, order);
    BN_rand_range(beta, order);
    BN_mul(alpha_times_beta, alpha, beta, ctx);

    EC_POINT_mul(group, commitmentPhi, alpha_times_beta, generator, bit_value,
                 ctx);
    EC_POINT_mul(group, commitmentA, alpha, NULL, NULL, ctx);
    EC_POINT_mul(group, commitmentB, beta, NULL, NULL, ctx);

    commitments[i].phi = commitmentPhi;
    commitments[i].A = commitmentA;
    commitments[i].B = commitmentB;
    commitments[i].alpha = alpha;
    commitments[i].beta = beta;

    pubs[i].phi = commitmentPhi;
    pubs[i].A = commitmentA;
    pubs[i].B = commitmentB;
  }

  // TODO: NIZK

  return pubs;
}

/**
 * @brief In the Round 1 phase, bidders send their public keys and NIZK
 *
 * @param step Current step of the auction, starting from 0
 * @return RoundOnePub
 */
RoundOnePub Bidder::roundOne(size_t step) {
  RoundOnePub pub;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *x = BN_new();
  BIGNUM *r = BN_new();
  EC_POINT *X = EC_POINT_new(group);
  EC_POINT *R = EC_POINT_new(group);

  BN_rand_range(x, order);
  BN_rand_range(r, order);
  EC_POINT_mul(group, X, x, NULL, NULL, ctx);
  EC_POINT_mul(group, R, r, NULL, NULL, ctx);

  keys[step].X = X;
  keys[step].R = R;
  keys[step].x = x;
  keys[step].r = r;

  pub.X = X;
  pub.R = R;

  // TODO: NIZK

  return pub;
}

/**
 * @brief In the Round 2 phase, bidders encode their bid bits
 *
 * @param pubs RoundOnePub in order of bidders id, including self
 * @param step Current step of the auction, starting from 0
 * @return RoundTwoPub
 */
RoundTwoPub Bidder::roundTwo(const std::vector<RoundOnePub> pubs, size_t step) {
  RoundTwoPub pub;
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *b = EC_POINT_new(group);
  int bit = binaryBidStr[step] - '0';

  if ((!junctionFlag && bit == 0) ||
      (junctionFlag && (bit == 0 || prevDecidingBit == 0))) {
    // PRINT_MESSAGE("Bidder " << id_ << " encodes bit 0 in step " << step)
    EC_POINT *firstHalfSum = EC_POINT_new(group);
    EC_POINT *secondHalfSum = EC_POINT_new(group);
    EC_POINT *Y = EC_POINT_new(group);

    EC_POINT_set_to_infinity(group, firstHalfSum);
    for (size_t i = 0; i < id_; ++i) {
      EC_POINT_add(group, firstHalfSum, firstHalfSum, pubs[i].X, ctx);
    }

    EC_POINT_set_to_infinity(group, secondHalfSum);
    for (size_t i = id_ + 1; i < pubs.size(); ++i) {
      EC_POINT_add(group, secondHalfSum, secondHalfSum, pubs[i].X, ctx);
    }

    EC_POINT_invert(group, secondHalfSum, ctx);
    EC_POINT_add(group, Y, firstHalfSum, secondHalfSum, ctx);
    EC_POINT_mul(group, b, NULL, Y, keys[step].x, ctx);
  } else { // (!junctionFlag && bit == 1) || (junctionFlag && bit == 1 &&
           // prevDecidingBit == 1))
    // PRINT_MESSAGE("Bidder " << id_ << " encodes bit 1 in step " << step)
    EC_POINT_mul(group, b, NULL, keys[step].R, keys[step].x, ctx);
  }

  pub.b = b;

  // TODO: NIZK

  return pub;
}

/**
 * @brief In the Round 3 phase, bidders send their encoded bid bits
 *
 * @param pubs RoundTwoPub in order of bidders id, including self
 * @param step Current step of the auction, starting from 0
 * @return size_t, 1 if winning bidder encodes bit 1 in this step, 0 otherwise
 */
size_t Bidder::roundThree(const std::vector<RoundTwoPub> pubs, size_t step) {
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *sum = EC_POINT_new(group);

  for (size_t i = 0; i < pubs.size(); ++i) {
    EC_POINT_add(group, sum, sum, pubs[i].b, ctx);
  }

  if (!EC_POINT_is_at_infinity(group, sum)) {
    // exist bidder encodes bit 1 in this step
    junctionFlag = true;
    prevDecidingStep = step;
    prevDecidingBit &= (binaryBidStr[step] - '0');
    maxBid |= (1 << (c_ - step - 1));
    return 1;
  }
  return 0;
}

/**
 * @brief Verify the commitments of all bidders
 *
 * @param pubs CommitmentPub in order of bidders id, including self
 * @return int, 0 if verification succeeds, 1 otherwise
 */
int Bidder::verifyCommitment(std::vector<CommitmentPub> pubs) {}

/**
 * @brief Verify the Round 1 messages of all bidders
 *
 * @param pubs RoundOnePub in order of bidders id, including self
 * @param step Current step of the auction, starting from 0
 * @return int, 0 if verification succeeds, 1 otherwise
 */
int Bidder::verifyRoundOne(std::vector<RoundOnePub> pubs, size_t step) {}

/**
 * @brief Verify the Round 2 messages of all bidders
 *
 * @param pubs RoundTwoPub in order of bidders id, including self
 * @param step Current step of the auction, starting from 0
 * @return int, 0 if verification succeeds, 1 otherwise
 */
int Bidder::verifyRoundTwo(std::vector<RoundTwoPub> pubs, size_t step) {}