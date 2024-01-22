#include "utils.h"
#include "params.h"

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

void handelSHA256Error(EVP_MD_CTX *md_ctx) {
  EVP_MD_CTX_free(md_ctx);
  PRINT_ERROR("Failed to calculate SHA256 hash.");
}

void SHA256inNIZKPoKDLog(BIGNUM *h, const EC_GROUP *group, const BIGNUM *order,
                         const EC_POINT *generator, const EC_POINT *g_to_v,
                         const EC_POINT *g_to_x, size_t id_, BN_CTX *ctx) {
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (md_ctx == NULL) {
    PRINT_ERROR("EVP_MD_CTX_new() failed.");
    return;
  }

  if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  const EC_POINT *points[] = {generator, g_to_v, g_to_x};
  for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); ++i) {
    unsigned char point_buf[EC_POINT_point2oct(
        group, points[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx)];
    if (EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED,
                           point_buf, sizeof(point_buf), ctx) == 0) {
      handelSHA256Error(md_ctx);
      return;
    }
    if (EVP_DigestUpdate(md_ctx, point_buf, sizeof(point_buf)) != 1) {
      handelSHA256Error(md_ctx);
      return;
    }
  }

  if (EVP_DigestUpdate(md_ctx, &id_, sizeof(id_)) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  if (EVP_DigestFinal_ex(md_ctx, hash, NULL) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  BN_bin2bn(hash, sizeof(hash), h); // h = hash(g, g^v, g^x, id_)
  BN_mod(h, h, order, ctx);
  EVP_MD_CTX_free(md_ctx);
}

void SHA256inNIZKPoWFCom(BIGNUM *h, const EC_GROUP *group, const BIGNUM *order,
                         const EC_POINT *generator, const EC_POINT *eps11,
                         const EC_POINT *eps12, const EC_POINT *eps21,
                         const EC_POINT *eps22, const EC_POINT *phi,
                         const EC_POINT *A, const EC_POINT *B, size_t id_,
                         BN_CTX *ctx) {
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (md_ctx == NULL) {
    PRINT_ERROR("EVP_MD_CTX_new() failed.");
    return;
  }

  if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  const EC_POINT *points[] = {generator, eps11, eps12, eps21, eps22, phi, A, B};
  for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); ++i) {
    unsigned char point_buf[EC_POINT_point2oct(
        group, points[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx)];
    if (EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED,
                           point_buf, sizeof(point_buf), ctx) == 0) {
      handelSHA256Error(md_ctx);
      return;
    }
    if (EVP_DigestUpdate(md_ctx, point_buf, sizeof(point_buf)) != 1) {
      handelSHA256Error(md_ctx);
      return;
    }
  }

  if (EVP_DigestUpdate(md_ctx, &id_, sizeof(id_)) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  if (EVP_DigestFinal_ex(md_ctx, hash, NULL) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  BN_bin2bn(hash, sizeof(hash),
            h); // h = hash(g, eps11, eps12, eps21, eps22, phi, A, B id_)
  BN_mod(h, h, order, ctx);
  EVP_MD_CTX_free(md_ctx);
}

void SHA256inNIZKPoWFStage1(BIGNUM *h, const EC_GROUP *group,
                            const BIGNUM *order, const EC_POINT *generator,
                            const EC_POINT *eps11, const EC_POINT *eps12,
                            const EC_POINT *eps13, const EC_POINT *eps14,
                            const EC_POINT *eps21, const EC_POINT *eps22,
                            const EC_POINT *eps23, const EC_POINT *eps24,
                            const EC_POINT *b, const EC_POINT *X,
                            const EC_POINT *Y, const EC_POINT *R,
                            const EC_POINT *c, const EC_POINT *A,
                            const EC_POINT *B, size_t id_, BN_CTX *ctx) {
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (md_ctx == NULL) {
    PRINT_ERROR("EVP_MD_CTX_new() failed.");
    return;
  }

  if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  const EC_POINT *points[] = {generator, eps11, eps12, eps13, eps14, eps21,
                              eps22,     eps23, eps24, b,     X,     Y,
                              R,         c,     A,     B};
  for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); ++i) {
    unsigned char point_buf[EC_POINT_point2oct(
        group, points[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx)];
    if (EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED,
                           point_buf, sizeof(point_buf), ctx) == 0) {
      handelSHA256Error(md_ctx);
      return;
    }
    if (EVP_DigestUpdate(md_ctx, point_buf, sizeof(point_buf)) != 1) {
      handelSHA256Error(md_ctx);
      return;
    }
  }

  if (EVP_DigestUpdate(md_ctx, &id_, sizeof(id_)) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  if (EVP_DigestFinal_ex(md_ctx, hash, NULL) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  BN_bin2bn(hash, sizeof(hash),
            h); // h = hash(g, eps11, eps12, eps13, eps14, eps21, eps22, eps23,
                // eps24, b, X, Y, R, c, A, B, id_)
  BN_mod(h, h, order, ctx);
  EVP_MD_CTX_free(md_ctx);
}

void SHA256inNIZKPoWFStage2(
    BIGNUM *h, const EC_GROUP *group, const BIGNUM *order,
    const EC_POINT *generator, const EC_POINT *eps11, const EC_POINT *eps12,
    const EC_POINT *eps13, const EC_POINT *eps11prime,
    const EC_POINT *eps12prime, const EC_POINT *eps13prime,
    const EC_POINT *eps21, const EC_POINT *eps22, const EC_POINT *eps23,
    const EC_POINT *eps21prime, const EC_POINT *eps22prime,
    const EC_POINT *eps23prime, const EC_POINT *eps31, const EC_POINT *eps32,
    const EC_POINT *eps31prime, const EC_POINT *eps32prime, const EC_POINT *Xi,
    const EC_POINT *Xj, const EC_POINT *A, const EC_POINT *Bi,
    const EC_POINT *Bj, const EC_POINT *B, const EC_POINT *Ri,
    const EC_POINT *Rj, const EC_POINT *Ci, const EC_POINT *Yi,
    const EC_POINT *Yj, size_t id_, BN_CTX *ctx) {
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (md_ctx == NULL) {
    PRINT_ERROR("EVP_MD_CTX_new() failed.");
    return;
  }

  if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  const EC_POINT *points[] = {
      generator,  eps11, eps12, eps13,      eps11prime, eps12prime,
      eps13prime, eps21, eps22, eps23,      eps21prime, eps22prime,
      eps23prime, eps31, eps32, eps31prime, eps32prime, Xi,
      Xj,         A,     Bi,    Bj,         B,          Ri,
      Rj,         Ci,    Yi,    Yj};
  for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); ++i) {
    unsigned char point_buf[EC_POINT_point2oct(
        group, points[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx)];
    if (EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED,
                           point_buf, sizeof(point_buf), ctx) == 0) {
      handelSHA256Error(md_ctx);
      return;
    }
    if (EVP_DigestUpdate(md_ctx, point_buf, sizeof(point_buf)) != 1) {
      handelSHA256Error(md_ctx);
      return;
    }
  }

  if (EVP_DigestUpdate(md_ctx, &id_, sizeof(id_)) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  if (EVP_DigestFinal_ex(md_ctx, hash, NULL) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  BN_bin2bn(hash, sizeof(hash),
            h); // h = hash(g, eps11, eps12, eps13, eps11', eps12', eps13'
                // eps21, eps22, eps23, eps21', eps22', eps23', eps31,
                // eps32, eps31', eps32', Xi, Xj, A, Bi, Bj, B,
                // Ri, Rj, Ci, Yi, Yj, id_)
  BN_mod(h, h, order, ctx);
  EVP_MD_CTX_free(md_ctx);
}