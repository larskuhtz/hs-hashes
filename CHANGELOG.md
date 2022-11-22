# Revision history for the hashes package

## 0.2.3 -- 2022-11-22

*   Support reset and reuse of context for OpenSSL digests.
*   Avoid the use of deprecated OpenSSL methods.
*   Add methods to write digests directly to a pointer for Keccak digests.

## 0.2.2.1 -- 2022-09-28

*   Support for Apple Silicon (`aarch64_HOST_ARCH`)

## 0.2.2.0 -- 2022-08-20

*   Test suite for SHA hash functions
*   Fix openssl-3.0 support

## 0.2.1.1 -- 2021-10-23

*   Fixes for building with GHC-9.2

## 0.2.1.0 -- 2021-10-22

*   Add OpenSSL based implementation of Keccak-512.

## 0.2.0.0 -- 2021-10-20

Breaking changes:

*   Add Class based interfaces for hash functions with pure and mutable
    contexts.
*   Support incremental hashing.
*   Provide type classes for hash functions with salt / key.
*   Add utility functions for hashing `ByteString`s.

Other changes:

*   Provide cryptographic hash functions from OpenSSL.

## 0.1.0.1 -- 2021-09-30

*   Support building with GHC-9.2.0-rc1

## 0.1.0.0 -- 2021-09-29

* First version. Released on an unsuspecting world.
