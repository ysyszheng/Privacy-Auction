#ifndef TYPES_H
#define TYPES_H

#include <openssl/ec.h>
#include <vector>

typedef struct {
  const EC_GROUP *group;
  const EC_POINT *g;
  const EC_POINT *g1;
  const EC_POINT *h;
  const BIGNUM *order;
} PubParams;

typedef struct {
  // const EC_POINT *T1; // FIXME: let T1=g1
  const EC_POINT *T2;
  const EC_POINT *G;
  const EC_POINT *H;
} OT_R1;

typedef std::vector<const OT_R1 *> OT_R1_VEC;

typedef struct {
  const EC_POINT *z;
  const EC_POINT *C0;
  const EC_POINT *C1;
} OT_S;

typedef std::vector<const OT_S *> OT_S_VEC;

#endif // TYPES_H
