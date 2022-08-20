#include <openssl/evp.h>
#include "keccak.h"

/* *************************************************************************** */
/* OpenSSL Master */

/*
int main()
{
    int ok = 1;
    unsigned int md_len = 0;
    MD_VALUE md_value;
    MD_VALUE_HEX result;
    EVP_MD *md;
    EVP_MD_CTX *ctx;

    CHECKED(md = EVP_get_digestbyname("KECCAK-256"));
    CHECKED(ctx = EVP_MD_CTX_new());
    CHECKED(EVP_DigestInit(ctx, md));
    CHECKED(EVP_DigestUpdate(ctx, msg, strlen(msg)));
    CHECKED(EVP_DigestFinal(ctx, md_value, &md_len));

    // Print Digest
    digestToHex(result, md_value);
    printf("Keccak-256 digest: %s\n", result);
    printf("expected         : %s\n", expected);

finally:
    if (ctx) EVP_MD_CTX_free(ctx);
    return ! ok;
}
*/

/* *************************************************************************** */
/* OpenSSL 1.1 and OpenSSL 3.0 */

/* The computation of the magic offset is base on the keccak_st structure in
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

/* OPENSSL 3.1 */
#if OPENSSL_VERSION_NUMBER >= 0x31000000L
#define SET_PAD_BYTE 

/* OPENSSL 3.0 */
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
#define GET_CTX(ctx) (*(((uint8_t **) ctx) + 7))
#define SET_PAD_BYTE (((uint8_t *) GET_CTX(ctx))[PAD_BYTE_OFFSET] = 0x01)

/* OPENSSL 1.1 */
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
#define GET_CTX(ctx) (EVP_MD_CTX_MD_data(ctx))
#define SET_PAD_BYTE (((uint8_t *) GET_CTX(ctx))[PAD_BYTE_OFFSET] = 0x01)

#endif

/* *************************************************************************** */
/* Implementation */


KECCAK256_CTX *keccak256_newctx()
{
    return EVP_MD_CTX_new();
}

KECCAK512_CTX *keccak512_newctx()
{
    return EVP_MD_CTX_new();
}

int keccak256_init(KECCAK256_CTX *ctx) {
    int ok = 1;
    const EVP_MD *md = NULL;
    CHECKED(md = EVP_get_digestbyname("SHA3-256"));
    CHECKED(EVP_DigestInit(ctx, md));
    SET_PAD_BYTE;
finally:
    return ok;
}

int keccak512_init(KECCAK512_CTX *ctx) {
    int ok = 1;
    const EVP_MD *md = NULL;
    CHECKED(md = EVP_get_digestbyname("SHA3-512"));
    CHECKED(EVP_DigestInit(ctx, md));
    SET_PAD_BYTE;
finally:
    return ok;
}

int keccak256_update(KECCAK256_CTX *ctx, const void *p, size_t l)
{
    return EVP_DigestUpdate(ctx, p, l);
}

int keccak512_update(KECCAK512_CTX *ctx, const void *p, size_t l)
{
    return EVP_DigestUpdate(ctx, p, l);
}

int keccak256_final(KECCAK256_CTX *ctx, unsigned char *md)
{
    unsigned int l;
    return EVP_DigestFinal(ctx, md, &l);
}

int keccak512_final(KECCAK512_CTX *ctx, unsigned char *md)
{
    unsigned int l;
    return EVP_DigestFinal(ctx, md, &l);
}

void keccak256_freectx(KECCAK256_CTX *ctx)
{
    return EVP_MD_CTX_free(ctx);
}

void keccak512_freectx(KECCAK512_CTX *ctx)
{
    return EVP_MD_CTX_free(ctx);
}

