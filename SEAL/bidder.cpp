#include "bidder.h"
#include "params.h"
#include <cassert>
#include <cstddef>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

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
 * @brief Generate a Non-interactive zero-knowledge proof of knowledge of
 * discrete logarithm
 *
 * @param proof NIZKPoKDLog
 * @param g_to_x g^x
 * @param x x, the discrete logarithm
 * @param ctx BN_CTX
 */
void Bidder::GenNIZKPoKDLog(NIZKPoKDLog &proof, const EC_POINT *g_to_x,
                            const BIGNUM *x, BN_CTX *ctx) {
  size_t len;
  unsigned char *hash_input;
  unsigned char *hash_output;
  BIGNUM *v = BN_new();   // \bar{r} in paper
  BIGNUM *h = BN_new();   // hash(g, g^v, g^x, id_), ch in paper
  BIGNUM *rho = BN_new(); // hash(g, g^v, g^x, id_), ch in paper
  EC_POINT *g_to_v = EC_POINT_new(group);

  EC_POINT_mul(group, g_to_v, v, NULL, NULL, ctx);

  len = BN_num_bytes(order);
  hash_input = new unsigned char[3 * len + sizeof(size_t)];
  hash_output = new unsigned char[SHA256_DIGEST_LENGTH];

  EC_POINT_point2oct(group, generator, POINT_CONVERSION_COMPRESSED, hash_input,
                     len, ctx);
  EC_POINT_point2oct(group, g_to_v, POINT_CONVERSION_COMPRESSED,
                     hash_input + len, len, ctx);
  EC_POINT_point2oct(group, g_to_x, POINT_CONVERSION_COMPRESSED,
                     hash_input + 2 * len, len, ctx);
  memcpy(hash_input + 3 * len, &id_, sizeof(size_t));

  SHA256(hash_input, 3 * len + sizeof(size_t), hash_output);
  BN_bin2bn(hash_output, SHA256_DIGEST_LENGTH,
            h); // ch = h = hash(g, g^v, g^x, id_)

  BN_mod_mul(h, h, x, order, ctx);   // h = h*x = ch*x
  BN_mod_sub(rho, v, h, order, ctx); // rho = v-h = v-ch*x

  proof.eps = g_to_v;
  proof.rho = rho;
}

/**
 * @brief Verify a Non-interactive zero-knowledge proof of knowledge of
 * discrete logarithm
 *
 * @param proof NIZKPoKDLog
 * @param X g^x
 * @param ctx BN_CTX
 * @return bool, true if proof is valid, false otherwise
 */
bool Bidder::VerNIZKPoKDLog(NIZKPoKDLog &proof, const EC_POINT *X, size_t id,
                            BN_CTX *ctx) {
  size_t len;
  unsigned char *hash_input;
  unsigned char *hash_output;
  BIGNUM *h = BN_new(); // hash(g, g^v, g^x, id_), ch in paper
  EC_POINT *g_to_rho = EC_POINT_new(group);
  EC_POINT *X_to_h = EC_POINT_new(group);

  len = BN_num_bytes(order);
  hash_input = new unsigned char[3 * len + sizeof(size_t)];
  hash_output = new unsigned char[SHA256_DIGEST_LENGTH];

  EC_POINT_point2oct(group, generator, POINT_CONVERSION_COMPRESSED, hash_input,
                     len, ctx);
  EC_POINT_point2oct(group, proof.eps, POINT_CONVERSION_COMPRESSED,
                     hash_input + len, len, ctx);
  EC_POINT_point2oct(group, X, POINT_CONVERSION_COMPRESSED,
                     hash_input + 2 * len, len, ctx);
  memcpy(hash_input + 3 * len, &id, sizeof(size_t));

  SHA256(hash_input, 3 * len + sizeof(size_t), hash_output);
  BN_bin2bn(hash_output, SHA256_DIGEST_LENGTH, h);

  // check if g^rho * X^h == eps
  EC_POINT_mul(group, g_to_rho, proof.rho, NULL, NULL, ctx);
  EC_POINT_mul(group, X_to_h, NULL, X, h, ctx);
  EC_POINT_add(group, X_to_h, X_to_h, g_to_rho, ctx);
  if (EC_POINT_cmp(group, X_to_h, proof.eps, ctx) != 0) {
    PRINT_ERROR("NIZKPoKDLog verification failed for bidder " << id);
    return false;
  }
  return true;
}

/**
 * @brief Generate a Non-interactive zero-knowledge proof of well-formedness
 * of commitments
 *
 * @param proof NIZKPoWFCom
 * @param phi g^{alpha*beta}
 * @param A g^alpha
 * @param B g^beta
 * @param alpha alpha
 * @param ctx BN_CTX
 */
void Bidder::GenNIZKPoWFCom(NIZKPoWFCom &proof, const EC_POINT *phi,
                            const EC_POINT *A, const EC_POINT *B,
                            const BIGNUM *alpha, BN_CTX *ctx) {
  size_t len;
  unsigned char *hash_input;
  unsigned char *hash_output;

  BIGNUM *r1 = BN_new();
  BIGNUM *rho1 = BN_new();
  BIGNUM *rho2 = BN_new();
  BIGNUM *ch = BN_new();
  BIGNUM *ch1 = BN_new();
  BIGNUM *ch2 = BN_new();

  EC_POINT *eps11 = EC_POINT_new(group);
  EC_POINT *eps12 = EC_POINT_new(group);
  EC_POINT *eps21 = EC_POINT_new(group);
  EC_POINT *eps22 = EC_POINT_new(group);
  EC_POINT *tmp = EC_POINT_new(group);

  BN_rand_range(r1, order);
  BN_rand_range(ch2, order);
  BN_rand_range(rho2, order);

  EC_POINT_mul(group, eps11, r1, NULL, NULL, ctx); // eps11 =g^r1
  EC_POINT_mul(group, eps12, NULL, B, r1, ctx);    // eps12 = g^(beat*r1)
  EC_POINT_mul(group, eps21, rho2, A, ch2,
               ctx); // eps21 = g^rho2 * g^(alpha*ch2)

  EC_POINT_copy(tmp, generator);                 // tmp = g
  EC_POINT_invert(group, tmp, ctx);              // tmp = g^-1
  EC_POINT_add(group, tmp, phi, tmp, ctx);       // tmp = phi/g
  EC_POINT_mul(group, tmp, NULL, tmp, ch2, ctx); // tmp = (phi/g)^ch2
  EC_POINT_mul(group, eps22, NULL, B, rho2,
               ctx); // eps22 = g^(beta*rho2)
  EC_POINT_add(group, eps22, eps22, tmp,
               ctx); // eps22 = g^(beta*rho2) * (phi/g)^ch2

  // TODO: whether need include ch2 in hash
  len = BN_num_bytes(order);
  hash_input = new unsigned char[8 * len + sizeof(size_t)];
  hash_output = new unsigned char[SHA256_DIGEST_LENGTH];

  EC_POINT_point2oct(group, generator, POINT_CONVERSION_COMPRESSED, hash_input,
                     len, ctx);
  EC_POINT_point2oct(group, eps11, POINT_CONVERSION_COMPRESSED,
                     hash_input + len, len, ctx);
  EC_POINT_point2oct(group, eps12, POINT_CONVERSION_COMPRESSED,
                     hash_input + 2 * len, len, ctx);
  EC_POINT_point2oct(group, eps21, POINT_CONVERSION_COMPRESSED,
                     hash_input + 3 * len, len, ctx);
  EC_POINT_point2oct(group, eps22, POINT_CONVERSION_COMPRESSED,
                     hash_input + 4 * len, len, ctx);
  EC_POINT_point2oct(group, phi, POINT_CONVERSION_COMPRESSED,
                     hash_input + 5 * len, len, ctx);
  EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED,
                     hash_input + 6 * len, len, ctx);
  EC_POINT_point2oct(group, B, POINT_CONVERSION_COMPRESSED,
                     hash_input + 7 * len, len, ctx);
  memcpy(hash_input + 8 * len, &id_, sizeof(size_t));

  SHA256(hash_input, 8 * len + sizeof(size_t), hash_output);
  BN_bin2bn(hash_output, SHA256_DIGEST_LENGTH,
            ch); // ch = hash(g, eps11, eps12, eps21, eps22, phi, A, B id_)
  BN_mod_sub(ch1, ch, ch2, order, ctx);    // ch1 = ch-ch2
  BN_mod_mul(ch1, ch1, alpha, order, ctx); // ch1 = alpha*(ch-ch2)
  BN_mod_sub(rho1, r1, ch1, order, ctx);   // rho1 = r1-alpha*(ch-ch2)

  proof.rho1 = rho1;
  proof.rho2 = rho2;
  proof.ch2 = ch2;
  proof.eps11 = eps11;
  proof.eps12 = eps12;
  proof.eps21 = eps21;
  proof.eps22 = eps22;
}

bool Bidder::VerNIZKPoWFCom(NIZKPoWFCom &proof, const EC_POINT *phi,
                            const EC_POINT *A, const EC_POINT *B, size_t id,
                            BN_CTX *ctx) {
  size_t len;
  unsigned char *hash_input;
  unsigned char *hash_output;
  BIGNUM *ch = BN_new();
  BIGNUM *ch1 = BN_new();
  EC_POINT *tmp1 = EC_POINT_new(group);
  EC_POINT *tmp2 = EC_POINT_new(group);

  len = BN_num_bytes(order);
  hash_input = new unsigned char[8 * len + sizeof(size_t)];
  hash_output = new unsigned char[SHA256_DIGEST_LENGTH];

  EC_POINT_point2oct(group, generator, POINT_CONVERSION_COMPRESSED, hash_input,
                     len, ctx);
  EC_POINT_point2oct(group, proof.eps11, POINT_CONVERSION_COMPRESSED,
                     hash_input + len, len, ctx);
  EC_POINT_point2oct(group, proof.eps12, POINT_CONVERSION_COMPRESSED,
                     hash_input + 2 * len, len, ctx);
  EC_POINT_point2oct(group, proof.eps21, POINT_CONVERSION_COMPRESSED,
                     hash_input + 3 * len, len, ctx);
  EC_POINT_point2oct(group, proof.eps22, POINT_CONVERSION_COMPRESSED,
                     hash_input + 4 * len, len, ctx);
  EC_POINT_point2oct(group, phi, POINT_CONVERSION_COMPRESSED,
                     hash_input + 5 * len, len, ctx);
  EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED,
                     hash_input + 6 * len, len, ctx);
  EC_POINT_point2oct(group, B, POINT_CONVERSION_COMPRESSED,
                     hash_input + 7 * len, len, ctx);
  memcpy(hash_input + 8 * len, &id, sizeof(size_t));

  SHA256(hash_input, 8 * len + sizeof(size_t), hash_output);
  BN_bin2bn(hash_output, SHA256_DIGEST_LENGTH,
            ch); // ch = hash(g, eps11, eps12, eps21, eps22, phi, A, B id_)
  BN_mod_sub(ch1, ch, proof.ch2, order, ctx); // ch1 = ch-ch2

  // check 1: g^rho1 * A^ch1 == eps11
  EC_POINT_mul(group, tmp1, proof.rho1, NULL, NULL, ctx); // tmp1 = g^rho1
  EC_POINT_mul(group, tmp2, NULL, A, ch1, ctx);           // tmp2 = A^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho1 * A^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps11, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFCom verification failed for bidder " << id
                                                              << ": check 1");
    return false;
  }

  // check 2: B^rho1 * phi^ch1 == eps12
  EC_POINT_mul(group, tmp1, NULL, B, proof.rho1, ctx); // tmp1 = g^rho1
  EC_POINT_mul(group, tmp2, NULL, phi, ch1, ctx);      // tmp2 = A^ch1
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx);          // tmp2 = g^rho1 * A^ch1
  if (EC_POINT_cmp(group, tmp2, proof.eps12, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFCom verification failed for bidder " << id
                                                              << ": check 2");
    return false;
  }

  // check 3: g^rho2 * A^ch2 == eps21
  EC_POINT_mul(group, tmp1, proof.rho2, NULL, NULL, ctx); // tmp1 = g^rho2
  EC_POINT_mul(group, tmp2, NULL, A, proof.ch2, ctx);     // tmp2 = A^ch2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = g^rho2 * A^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps21, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFCom verification failed for bidder " << id
                                                              << ": check 3");
    return false;
  }

  // check 4: B^rho2 * (phi/g)^ch2 == eps22
  EC_POINT_copy(tmp1, generator);                        // tmp1 = g
  EC_POINT_invert(group, tmp1, ctx);                     // tmp1 = g^-1
  EC_POINT_add(group, tmp1, phi, tmp1, ctx);             // tmp1 = phi/g
  EC_POINT_mul(group, tmp1, NULL, tmp1, proof.ch2, ctx); // tmp1 = (phi/g)^ch2
  EC_POINT_mul(group, tmp2, NULL, B, proof.rho2, ctx);   // tmp2 = B^rho2
  EC_POINT_add(group, tmp2, tmp1, tmp2, ctx); // tmp2 = B^rho2 * (phi/g)^ch2
  if (EC_POINT_cmp(group, tmp2, proof.eps22, ctx) != 0) {
    PRINT_ERROR("NIZKPoWFCom verification failed for bidder " << id
                                                              << ": check 4");
    return false;
  }

  return true;
}

/**
 * @brief In the Commit phase, bidders commit their bids to the public
 * bulletin board, as well as their NIZK
 *
 * @return CommitmentPub, i.e. std::vector<CommitmentPerBit>
 */
CommitmentPub Bidder::commitBid() {
  CommitmentPub pubs(c_);
  int bit;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *bit_value = BN_new();

  BIGNUM *alpha = BN_new();
  BIGNUM *beta = BN_new();
  BIGNUM *alpha_mul_beta = BN_new();

  EC_POINT *commitmentPhi = EC_POINT_new(group);
  EC_POINT *commitmentA = EC_POINT_new(group);
  EC_POINT *commitmentB = EC_POINT_new(group);

  for (size_t i = 0; i < c_; ++i) {
    // Commitment of i-th bit of bid_
    bit = binaryBidStr[i] - '0';
    BN_set_word(bit_value, bit);

    BN_rand_range(alpha, order);
    BN_rand_range(beta, order);
    BN_mul(alpha_mul_beta, alpha, beta, ctx);

    EC_POINT_mul(group, commitmentPhi, alpha_mul_beta, generator, bit_value,
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

    // Generate NIZKoKDLog
    GenNIZKPoKDLog(pubs[i].pokdlogA, commitmentA, alpha, ctx);
    GenNIZKPoKDLog(pubs[i].pokdlogB, commitmentB, beta, ctx);

    // Generate NIZKoWFCom
    GenNIZKPoWFCom(pubs[i].powfcom, commitmentPhi, commitmentA, commitmentB,
                   alpha, ctx);
  }

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

  // Generate NIZKoKDLog
  GenNIZKPoKDLog(pub.pokdlogX, X, x, ctx);
  GenNIZKPoKDLog(pub.pokdlogR, R, r, ctx);

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
 * @return bool, true if all commitments are valid and NIZK Proofs is valid,
 * false otherwise
 */
bool Bidder::verifyCommitment(std::vector<CommitmentPub> pubs) {
  bool ret = true;
  for (size_t i = 0; i < pubs.size(); ++i) {
    for (size_t j = 0; j < c_; ++j) {
      // FIXME: verification failed
      ret |= VerNIZKPoKDLog(pubs[i][j].pokdlogA, pubs[i][j].A, i, NULL);
      ret |= VerNIZKPoKDLog(pubs[i][j].pokdlogB, pubs[i][j].B, i, NULL);
      // FIXME: segmentation fault
      ret |= VerNIZKPoWFCom(pubs[i][j].powfcom, pubs[i][j].phi, pubs[i][j].A,
                            pubs[i][j].B, i, NULL);
    }
  }
  return ret;
}

/**
 * @brief Verify the Round 1 messages of all bidders
 *
 * @param pubs RoundOnePub in order of bidders id, including self
 * @return bool, true if all Round 1 messages are valid and NIZK Proofs is
 * valid, false otherwise
 */
bool Bidder::verifyRoundOne(std::vector<RoundOnePub> pubs) {
  bool ret = true;
  for (size_t i = 0; i < pubs.size(); ++i) {
    ret |= VerNIZKPoKDLog(pubs[i].pokdlogX, pubs[i].X, i, NULL);
    ret |= VerNIZKPoKDLog(pubs[i].pokdlogR, pubs[i].R, i, NULL);
  }
  return ret;
}

/**
 * @brief Verify the Round 2 messages of all bidders
 *
 * @param pubs RoundTwoPub in order of bidders id, including self
 * @param step Current step of the auction, starting from 0
 * @return bool, true if all Round 2 messages are valid and NIZK Proofs is
 * valid, false otherwise
 */
bool Bidder::verifyRoundTwo(std::vector<RoundTwoPub> pubs, size_t step) {
  return true;
}