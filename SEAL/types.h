#include <openssl/ec.h>
#include <vector>

struct CommitmentPerBit {
  EC_POINT *phi;
  EC_POINT *A;
  EC_POINT *B;
  // TODO: NIZK
};

typedef std::vector<CommitmentPerBit> CommitmentPub;

struct RoundOnePub {
  EC_POINT *X;
  EC_POINT *R;
  // TODO: NIZK
};

struct RoundTwoPub {
  EC_POINT *b;
  // TODO: NIZK
};
