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
    if (ctx) keccak256_freectx(ctx);
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
 * sizeof(uint64_t) * 40 + size_of(size_t) * 3 + (1600 / 8 - 32)
 *
 * On a 64bit platform this number is 392
 */

// struct keccak_st {
//     uint64_t A[5][5];
//     size_t block_size;          /* cached ctx->digest->block_size */
//     size_t md_size;             /* output length, variable in XOF */
//     size_t bufsz;               /* used bytes in below buffer */
//     unsigned char buf[KECCAK1600_WIDTH / 8 - 32];
//     unsigned char pad;
// };

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

#if OPENSSL_VERSION_NUMBER >= 0x31000000L
int keccak256_init(KECCAK256_CTX *ctx) {
    int ok = 1;
    const EVP_MD *md = NULL;
    CHECKED(md = EVP_get_digestbyname("KECCAK-256"));
    CHECKED(EVP_DigestInit(ctx, md));
finally:
    return ok;
}

int keccak512_init(KECCAK512_CTX *ctx) {
    int ok = 1;
    const EVP_MD *md = NULL;
    CHECKED(md = EVP_get_digestbyname("KECCAK-512"));
    CHECKED(EVP_DigestInit(ctx, md));
finally:
    return ok;
}

#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
int keccak256_init(KECCAK256_CTX *ctx) {
    int ok = 1;
    const EVP_MD *md = NULL;
    int padByteOffset = 25 * sizeof(uint64_t) + 3 * sizeof(size_t) + 1600/8 - 32;
    CHECKED(md = EVP_sha3_256());
    CHECKED(EVP_DigestInit(ctx, md));

    // MAGIC (set padding char to 0x1)
    ((uint8_t *) ctx)[padByteOffset] = 0x01;
finally:
    return ok;
}

int keccak512_init(KECCAK512_CTX *ctx) {
    int ok = 1;
    const EVP_MD *md = NULL;
    int padByteOffset = 25 * sizeof(uint64_t) + 3 * sizeof(size_t) + 1600/8 - 32;
    CHECKED(md = EVP_sha3_512());
    CHECKED(EVP_DigestInit(ctx, md));

    // MAGIC (set padding char to 0x1)
    ((uint8_t *) ctx)[padByteOffset] = 0x01;
finally:
    return ok;
}

#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
int keccak256_init(KECCAK256_CTX *ctx) {
    int ok = 1;
    const EVP_MD *md = NULL;
    int padByteOffset = 25 * sizeof(uint64_t) + 3 * sizeof(size_t) + 1600/8 - 32;
    CHECKED(md = EVP_sha3_256());
    CHECKED(EVP_DigestInit(ctx, md));

    // MAGIC (set padding char to 0x1)
    ((uint8_t *) EVP_MD_CTX_md_data(ctx))[padByteOffset] = 0x01;
finally:
    return ok;
}

int keccak512_init(KECCAK512_CTX *ctx) {
    int ok = 1;
    const EVP_MD *md = NULL;
    int padByteOffset = 25 * sizeof(uint64_t) + 3 * sizeof(size_t) + 1600/8 - 32;
    CHECKED(md = EVP_sha3_512());
    CHECKED(EVP_DigestInit(ctx, md));

    // MAGIC (set padding char to 0x1)
    ((uint8_t *) EVP_MD_CTX_md_data(ctx))[padByteOffset] = 0x01;
finally:
    return ok;
}
#endif

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


