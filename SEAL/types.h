#include <openssl/ec.h>

// FIXME: two-dimensional array
struct CommitmentPub {
  EC_POINT *phi;
  EC_POINT *A;
  EC_POINT *B;
  // TODO: NIZK
};

struct RoundOnePub {
  EC_POINT *X;
  EC_POINT *R;
  // TODO: NIZK
};

struct RoundTwoPub {
  EC_POINT *b;
  // TODO: NIZK
};