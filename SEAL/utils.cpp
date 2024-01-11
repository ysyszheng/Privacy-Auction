#include "utils.h"

std::string uchar2hex(const unsigned char *data, size_t len) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << static_cast<unsigned>(data[i]);
  }
  return ss.str();
}

std::string char2hex(const char *data, size_t len) {
  return uchar2hex(reinterpret_cast<const unsigned char *>(data), len);
}

BIGNUM *SHA256inNIZKPoKDLog(const EC_GROUP *group, const BIGNUM *order,
                            const EC_POINT *generator, const EC_POINT *g_to_v,
                            const EC_POINT *g_to_x, size_t id_, BN_CTX *ctx) {
  BIGNUM *h = BN_new();
  unsigned char *hash_input;
  unsigned char *hash_output;
  size_t len = BN_num_bytes(order);

  hash_input = new unsigned char[3 * len + sizeof(size_t)];
  hash_output = new unsigned char[SHA256_DIGEST_LENGTH];

  memcpy(hash_input,
         EC_POINT_point2hex(group, generator, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + len,
         EC_POINT_point2hex(group, g_to_v, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 2 * len,
         EC_POINT_point2hex(group, g_to_x, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 3 * len, &id_, sizeof(size_t));

  SHA256(hash_input, 3 * len + sizeof(size_t), hash_output);
  BN_bin2bn(hash_output, SHA256_DIGEST_LENGTH,
            h); // ch = h = hash(g, g^v, g^x, id_)
  BN_mod(h, h, order, ctx);

  return h;
}

BIGNUM *SHA256inNIZKPoWFCom(const EC_GROUP *group, const BIGNUM *order,
                            const EC_POINT *generator, const EC_POINT *eps11,
                            const EC_POINT *eps12, const EC_POINT *eps21,
                            const EC_POINT *eps22, const EC_POINT *phi,
                            const EC_POINT *A, const EC_POINT *B, size_t id_,
                            BN_CTX *ctx) {
  BIGNUM *h = BN_new();
  unsigned char *hash_input;
  unsigned char *hash_output;
  size_t len = BN_num_bytes(order);

  hash_input = new unsigned char[8 * len + sizeof(size_t)];
  hash_output = new unsigned char[SHA256_DIGEST_LENGTH];

  memcpy(hash_input,
         EC_POINT_point2hex(group, generator, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + len,
         EC_POINT_point2hex(group, eps11, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 2 * len,
         EC_POINT_point2hex(group, eps12, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 3 * len,
         EC_POINT_point2hex(group, eps21, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 4 * len,
         EC_POINT_point2hex(group, eps22, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 5 * len,
         EC_POINT_point2hex(group, phi, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 6 * len,
         EC_POINT_point2hex(group, A, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 7 * len,
         EC_POINT_point2hex(group, B, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 8 * len, &id_, sizeof(size_t));

  SHA256(hash_input, 8 * len + sizeof(size_t), hash_output);
  BN_bin2bn(hash_output, SHA256_DIGEST_LENGTH,
            h); // h = hash(g, eps11, eps12, eps21, eps22, phi, A, B id_)
  BN_mod(h, h, order, ctx);

  return h;
}

BIGNUM *SHA256inNIZKPoWFStage1(
    const EC_GROUP *group, const BIGNUM *order, const EC_POINT *generator,
    const EC_POINT *eps11, const EC_POINT *eps12, const EC_POINT *eps13,
    const EC_POINT *eps14, const EC_POINT *eps21, const EC_POINT *eps22,
    const EC_POINT *eps23, const EC_POINT *eps24, const EC_POINT *b,
    const EC_POINT *X, const EC_POINT *Y, const EC_POINT *R, const EC_POINT *c,
    const EC_POINT *A, const EC_POINT *B, size_t id_, BN_CTX *ctx) {
  BIGNUM *h = BN_new();
  unsigned char *hash_input;
  unsigned char *hash_output;
  size_t len = BN_num_bytes(order);

  hash_input = new unsigned char[16 * len + sizeof(size_t)];
  hash_output = new unsigned char[SHA256_DIGEST_LENGTH];

  memcpy(hash_input,
         EC_POINT_point2hex(group, generator, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + len,
         EC_POINT_point2hex(group, eps11, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 2 * len,
         EC_POINT_point2hex(group, eps12, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 3 * len,
         EC_POINT_point2hex(group, eps13, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 4 * len,
         EC_POINT_point2hex(group, eps14, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 5 * len,
         EC_POINT_point2hex(group, eps21, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 6 * len,
         EC_POINT_point2hex(group, eps22, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 7 * len,
         EC_POINT_point2hex(group, eps23, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 8 * len,
         EC_POINT_point2hex(group, eps24, POINT_CONVERSION_COMPRESSED, ctx),
         len);
  memcpy(hash_input + 9 * len,
         EC_POINT_point2hex(group, b, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 10 * len,
         EC_POINT_point2hex(group, X, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 11 * len,
         EC_POINT_point2hex(group, Y, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 12 * len,
         EC_POINT_point2hex(group, R, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 13 * len,
         EC_POINT_point2hex(group, c, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 14 * len,
         EC_POINT_point2hex(group, A, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 15 * len,
         EC_POINT_point2hex(group, B, POINT_CONVERSION_COMPRESSED, ctx), len);
  memcpy(hash_input + 16 * len, &id_, sizeof(size_t));

  SHA256(hash_input, 16 * len + sizeof(size_t), hash_output);
  BN_bin2bn(hash_output, SHA256_DIGEST_LENGTH,
            h); // h = hash(g, eps11, eps12, eps13, eps14, eps21, eps22,
                // eps23, eps24, b, X, Y, R, c, A, B, id_)
  BN_mod(h, h, order, ctx);

  return h;
}
