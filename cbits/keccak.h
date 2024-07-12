/*
 * Copyright: Copyright © 2021-2024 Lars Kuhtz <lakuhtz@gmail.com>
 * License: MIT
 * Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
 */

#include <openssl/evp.h>

/* *************************************************************************** */
/* Generic Tools */

#define CHECKED(f)            \
    if (! (f)) {              \
        ok = 0; goto finally; \
    }

/* *************************************************************************** */
/* Keccak */

/* Keccak is supported directly in OpenSSL >= 2.3. No legacy implementation is
 * provided in this case.
 */

#if OPENSSL_VERSION_NUMBER < 0x30200000L
int keccak_EVP_DigestInit_ex(EVP_MD_CTX *ctx, EVP_MD *md);
#endif
