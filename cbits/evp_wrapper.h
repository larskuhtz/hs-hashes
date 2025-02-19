#ifndef EVP_WRAPPER_H
#define EVP_WRAPPER_H

#include <stddef.h>

int EVP_DigestUpdate(void*, const void*, size_t);
int EVP_DigestFinal_ex(void*, unsigned char*, unsigned int*);
int EVP_DigestFinalXOF(void*, unsigned char*, size_t);

#define EVP_DigestUpdate_off(ctx, data, off, count) \
    EVP_DigestUpdate((ctx), ((data) + (off)), (count))

#define EVP_DigestFinal_ex_off(ctx, data, off, sptr) \
    EVP_DigestFinal_ex((ctx), ((data) + (off)), (sptr))

#define EVP_DigestFinalXOF_off(ctx, data, off, count) \
    EVP_DigestFinalXOF((ctx), ((data) + (off)), (count))

#endif // EVP_WRAPPER_H
