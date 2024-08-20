/*
 * Copyright: Copyright © 2021-2024 Lars Kuhtz <lakuhtz@gmail.com>
 * License: MIT
 * Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
 */

#include <openssl/evp.h>
#include "keccak.h"

/* *************************************************************************** */
/* Legacy support for Keccak for OpenSSL prior to version 3.2
 *
 * Support for Keccak-224, Keccak-256, Keccak-384, and Keccak-512 was added
 * in OpenSSL version 3.2.
 *
 * History (cf. https://openssl.org/policies/releasestrat.html)
 *
 * - OpenSSL 1.1: Support ended 2023-09-11.
 * - OpenSSL 3.0: Support ends 2026-09-07 (LTS).
 * - OpenSSL 3.1: Support ends 2025-03-14.
 * - OpenSSL 3.2: Native Keccak support added.
 *
 * This file also adds supports for those digests for OpenSSL versions 1.1
 * onward.
 *
 * Keccak differs from NIST standardized SHA3 by using a different padding
 * value. This implementation uses low-level internals of the SHA3
 * implementation for overwriting the padding byte.
 */

/* *************************************************************************** */
/* OpenSSL 1.1 and OpenSSL 3.0 */

/* The computation of the magic offset is based on the keccak_st structure in
 * OpenSSL-1.1 and OpenSSL-3.0
 *
 * Assuming conventional alignment, the bytes offset is
 *
 * sizeof(uint64_t) * 25 + size_of(size_t) * 3 + (1600 / 8 - 32)
 *
 * On a 64bit platform this number is 392
 *
 * // struct keccak_st {
 * //     uint64_t A[5][5];
 * //     size_t block_size;
 * //     size_t md_size;
 * //     size_t bufsz;
 * //     unsigned char buf[KECCAK1600_WIDTH / 8 - 32];
 * //     unsigned char pad;
 * // };
 *
 * For OpenSSL 1.1 this context is stored in EVP_MD_CTX as data and is accessed
 * via EVP_CTX_MD_md_data().
 *
 * For OpenSSL 3.0 it is stored in EVP_MD_CTX in the algctx field. The structure
 * is a field of pointers and algctx is the 8th pointer.
 *
 * // struct evp_md_ctx_st {
 * //   const EVP_MD *reqdigest;
 * //   const EVP_MD *digest;
 * //   ENGINE *engine;
 * //   unsigned long flags;
 * //   void *md_data;
 * //   EVP_PKEY_CTX *pctx;
 * //   int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
 * //
 * //   // Opaque ctx returned from a providers digest algorithm implementation
 * //   // OSSL_FUNC_digest_newctx()
 * //   //
 * //   void *algctx;
 * //   EVP_MD *fetched_digest;
 * // }
 */

#define PAD_BYTE_OFFSET (25 * sizeof(uint64_t) + 3 * sizeof(size_t) + 1600/8 - 32)

/* OPENSSL 3.2 */
#if OPENSSL_VERSION_NUMBER >= 0x30200000L

/* Keccak is supported directly in OpenSSL >= 2.3. No legacy implementation is
 * provided in this case.
 */

/* OPENSSL 3.0 (use with algorithm name "SHA3") */
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
#define GET_CTX(ctx) (*(((uint8_t **) ctx) + 7))
#define SET_PAD_BYTE (((uint8_t *) GET_CTX(ctx))[PAD_BYTE_OFFSET] = 0x01)

/* OPENSSL 1.1 (use with algorithm name "SHA3") */
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
#define GET_CTX(ctx) ((uint8_t *) EVP_MD_CTX_md_data(ctx))
#define SET_PAD_BYTE (GET_CTX(ctx)[PAD_BYTE_OFFSET] = 0x01)

#else
#error "Unsupported OpenSSL version. Please install OpenSSL >= 1.1.0"

#endif

/* *************************************************************************** */
/* Implementation */

#if OPENSSL_VERSION_NUMBER < 0x30200000L
int keccak_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *md) {
    int ok = 1;
    CHECKED(EVP_DigestInit_ex(ctx, md, NULL));
    SET_PAD_BYTE;
finally:
    return ok;
}
#endif

