Haskell implementation of various hash functions.

## Available Hash functions

### Native Haskell Implementations

*   SipHash
    *   SipHash-2-4
    *   SipHash-1-3
    *   SipHash-4-8
    *   SipHash-c-d (c rounds per block and d finalization rounds)
*   FNV1 (64 bit, 32 bit, and host word size)
*   FNV1a (64 bit, 32 bit, and host word size)

## Linked from OpenSSL

The following hash functions are available with the package is build with
`-f+with-openssl`, which is the default.

A version of OpenSSL of at least version 1.1 must be available on the system at
a location for Cabal/GHC can find it.

*   SHA2
    *   SHA2-224
    *   SHA2-256
    *   SHA2-384
    *   SHA2-512
    *   SHA2-512_224 (SHA512 truncated to 224 bits)
    *   SHA2-512_256 (SHA512 truncated to 256 bits)
*   SHA3
    *   SHA3_224
    *   SHA3_256
    *   SHA3_384
    *   SHA3_512
    *   SHAKE-128
    *   SHAKE-256
*   BLAKE2
    *   BLAKE2s256
    *   BLAKE2b512
*   KECCAK
    *   KECCAK-256
    *   KECCAK-512
    See comment in [Data.Hash.Keccak](https://github.com/larskuhtz/hs-hashes/blob/main/src/Data/Hash/Keccak.hs) before using these Keccak implementations.


