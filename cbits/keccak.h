#include <openssl/evp.h>

/* *************************************************************************** */
/* Generic Tools */

#define CHECKED(f)            \
    if (! (f)) {              \
        ok = 0; goto finally; \
    }

/* *************************************************************************** */
/* Keccak */

typedef EVP_MD_CTX KECCAK256_CTX;
typedef EVP_MD_CTX KECCAK512_CTX;

// KECCAK-256
KECCAK256_CTX *keccak256_newctx();
int keccak256_init(KECCAK256_CTX *ctx);
int keccak256_update(KECCAK256_CTX *ctx, const void *p, size_t l);
int keccak256_final(KECCAK256_CTX *ctx, unsigned char *md);
void keccak256_freectx(KECCAK256_CTX *ctx);

// KECCAK-512
KECCAK512_CTX *keccak512_newctx();
int keccak512_init(KECCAK512_CTX *ctx);
int keccak512_update(KECCAK512_CTX *ctx, const void *p, size_t l);
int keccak512_final(KECCAK512_CTX *ctx, unsigned char *md);
void keccak512_freectx(KECCAK512_CTX *ctx);

