#ifndef TYPES_H
#define TYPES_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <vector>

/**
 * @brief Non-interactive zero-knowledge proof of knowledge of discrete
 * logarithm
 *
 */
typedef struct {
  EC_POINT *eps;
  BIGNUM *rho;
} NIZKPoKDLog;

/**
 * @brief Non-interactive zero-knowledge proof of well-formedness
 * of commitments
 *
 */
typedef struct {
  EC_POINT *eps11;
  EC_POINT *eps12;
  EC_POINT *eps21;
  EC_POINT *eps22;

  BIGNUM *rho1;
  BIGNUM *rho2;

  BIGNUM
      *ch2; // only send one of ch1 and ch2 to save bandwidth, here we send ch2
} NIZKPoWFCom;

/**
 * @brief Non-interactive zero-knowledge proof of well-formedness
 * of cryptograms in Stage 1 (before junction)
 *
 */
typedef struct {
  EC_POINT *eps11;
  EC_POINT *eps12;
  EC_POINT *eps13;
  EC_POINT *eps14;
  EC_POINT *eps21;
  EC_POINT *eps22;
  EC_POINT *eps23;
  EC_POINT *eps24;

  BIGNUM *rho11;
  BIGNUM *rho12;
  BIGNUM *rho21;
  BIGNUM *rho22;

  BIGNUM *ch2;
} NIZKPoWFStage1;

/**
 * @brief Non-interactive zero-knowledge proof of well-formedness
 * of cryptograms in Stage 2 (after junction)
 *
 */
typedef struct {
  EC_POINT *eps11;
  EC_POINT *eps12;
  EC_POINT *eps13;
  EC_POINT *eps11prime;
  EC_POINT *eps12prime;
  EC_POINT *eps13prime;
  EC_POINT *eps21;
  EC_POINT *eps22;
  EC_POINT *eps23;
  EC_POINT *eps21prime;
  EC_POINT *eps22prime;
  EC_POINT *eps23prime;
  EC_POINT *eps31;
  EC_POINT *eps32;
  EC_POINT *eps31prime;
  EC_POINT *eps32prime;

  BIGNUM *rho11;
  BIGNUM *rho12;
  BIGNUM *rho13;
  BIGNUM *rho21;
  BIGNUM *rho22;
  BIGNUM *rho23;
  BIGNUM *rho31;
  BIGNUM *rho32;

  BIGNUM *ch2;
  BIGNUM *ch3;
} NIZKPoWFStage2;

typedef struct {
  // Commitments
  EC_POINT *phi;
  EC_POINT *A;
  EC_POINT *B;

  // showing knowledge of DLogA and DLogB
  NIZKPoKDLog pokdlogA;
  NIZKPoKDLog pokdlogB;

  // showing well-formedness of Commitments
  NIZKPoWFCom powfcom;
} CommitmentPerBit;

typedef std::vector<CommitmentPerBit> CommitmentPub;

typedef struct {
  // Public keys
  EC_POINT *X;
  EC_POINT *R;

  // showing knowledge of DLogX and DLogR, i.e. well-formedness of public keys
  NIZKPoKDLog pokdlogX;
  NIZKPoKDLog pokdlogR;
} RoundOnePub;

typedef struct {
  EC_POINT *b;
  EC_POINT *Y;
  EC_POINT *X;
  EC_POINT *R;
} AuxilaryInfoPerBidder;

typedef std::vector<AuxilaryInfoPerBidder> AuxilaryInfo;

typedef enum { STAGE1, STAGE2 } stagetype_t;

typedef struct {
  // Encoded bids
  EC_POINT *b;

  // Showing well-formedness of cryptograms
  stagetype_t stage; // STAGE1 or STAGE2
  union {
    // shwoin well-formedness of cryptograms in Stage 1 (before junction)
    NIZKPoWFStage1 powfstage1;
    // shwoin well-formedness of cryptograms in Stage 2 (after junction)
    NIZKPoWFStage2 powfstage2;
  } powf;
} RoundTwoPub;

#endif // TYPES_H
