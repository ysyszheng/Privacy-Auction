#ifndef TYPES_H
#define TYPES_H

#include <openssl/ec.h>

typedef struct {
  const EC_GROUP *group;
  const EC_POINT *g;
  const EC_POINT *g1;
  const EC_POINT *h;
  const BIGNUM *order;
} PubParams;

typedef struct {
  const EC_POINT *T1;
  const EC_POINT *T2;
  const EC_POINT *G;
  const EC_POINT *H;
} OT_R1;

typedef struct {
  const EC_POINT *z;
  const EC_POINT *C0;
  const EC_POINT *C1;
} OT_S;

#endif // TYPES_H
