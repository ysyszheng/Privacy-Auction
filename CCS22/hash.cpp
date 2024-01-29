#include "hash.h"
#include <cstddef>

void handelSHA256Error(EVP_MD_CTX *md_ctx) {
  EVP_MD_CTX_free(md_ctx);
  PRINT_ERROR("Failed to calculate SHA256 hash.");
}

void SHA256inSetup(BIGNUM *h, const BIGNUM *order, const BIGNUM *bns[],
                   size_t array_len, BN_CTX *ctx) {
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

  for (size_t i = 0; i < array_len; ++i) {
    int len = BN_num_bytes(bns[i]);
    unsigned char *point_buf = (unsigned char *)OPENSSL_malloc(len);
    if (point_buf == NULL) {
      handelSHA256Error(md_ctx);
      return;
    }

    len = BN_bn2bin(bns[i], point_buf);
    if (len == 0) {
      handelSHA256Error(md_ctx);
      OPENSSL_free(point_buf);
      return;
    }

    if (EVP_DigestUpdate(md_ctx, point_buf, len) != 1) {
      handelSHA256Error(md_ctx);
      OPENSSL_free(point_buf);
      return;
    }

    OPENSSL_free(point_buf);
  }

  if (EVP_DigestFinal_ex(md_ctx, hash, NULL) != 1) {
    handelSHA256Error(md_ctx);
    return;
  }

  BN_bin2bn(hash, sizeof(hash), h);
  BN_mod(h, h, order, ctx);
  EVP_MD_CTX_free(md_ctx);
}
