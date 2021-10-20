#include <string.h>
#include "keccak.h"

/* *************************************************************************** */
/* Generic Tools */

#define CHECKED(f)             \
    if (! (f)) {               \
        ok = 0; goto finally; \
    }

/* *************************************************************************** */
/* Digests */

typedef unsigned char MD_VALUE[32];
typedef char MD_VALUE_HEX[32*2+1];

void digestToHex(char *result, const unsigned char *md_value) {
    int i;
    for (i = 0; i < 32; i++) {
        sprintf(&result[2*i], "%02x", (uint8_t) (md_value[i]));
    }
}

const char *msg = "testing";
const char *expected = "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02";

/* *************************************************************************** */
/* Main */

int main()
{
    int ok = 1;
    MD_VALUE md_value;
    MD_VALUE_HEX result;
    KECCAK256_CTX *ctx = NULL;

    CHECKED(ctx = keccak256_newctx());
    CHECKED(keccak256_init(ctx));
    CHECKED(keccak256_update(ctx, msg, strlen(msg)));
    CHECKED(keccak256_final(ctx, md_value));
    digestToHex(result, md_value);
    printf("Keccak-256 digest: %s\n", result);
    printf("expected         : %s\n", expected);

finally:
    if (ctx) keccak256_freectx(ctx);
    return ! ok;
}
