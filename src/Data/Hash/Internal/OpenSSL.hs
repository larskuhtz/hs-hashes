{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

#include <openssl/opensslv.h>

-- |
-- Module: Data.Hash.Internal.OpenSSL
-- Copyright: Copyright © 2021-2024 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Bindings for OpenSSL EVP Message Digest Routines.
--
-- Requires OpenSSL version >= 1.1.0
--
module Data.Hash.Internal.OpenSSL
(

-- * EVP digest routines

  Algorithm(..)
, Ctx(..)
, Digest(..)
, resetCtx
, initCtx
, updateCtx
, finalCtx
, fetchAlgorithm

-- * Algorithms

, OpenSslDigest(..)
, OpenSslException(..)

-- ** SHA2
--
-- $sha2

, Sha2_224(..)
, Sha2_256(..)
, Sha2_384(..)
, Sha2_512(..)
, Sha2_512_224(..)
, Sha2_512_256(..)

-- ** SHA3
--
-- $sha3

, Sha3_224(..)
, Sha3_256(..)
, Sha3_384(..)
, Sha3_512(..)
, Shake128(..)
, type Shake128_256
, Shake256(..)
, type Shake256_512

-- ** Keccak
--
-- $keccak

, Keccak224(..)
, Keccak256(..)
, Keccak384(..)
, Keccak512(..)

-- *** Unsafe finalize functions
, finalizeKeccak256Ptr
, finalizeKeccak512Ptr

-- ** Blake2
--
-- $blake2

, Blake2b512(..)
, Blake2s256(..)
) where

import Control.Exception
import Control.Monad

import Data.ByteString.Short qualified as BS
import Data.Typeable
import Data.Void
import Data.Word

import Foreign.C.String (CString, withCString)
import Foreign.ForeignPtr
import Foreign.Marshal
import Foreign.Ptr

import GHC.Exts
import GHC.IO
import GHC.TypeNats

-- internal modules

import Data.Hash.Class.Mutable
import Data.Hash.Internal.Utils

-- -------------------------------------------------------------------------- --
-- Check OpenSSL Version
--
-- OpenSSL Release History (cf. https://openssl.org/policies/releasestrat.html)
--
-- - OpenSSL 1.1: Support ended 2023-09-11.
-- - OpenSSL 3.0: Support ends 2026-09-07 (LTS).
-- - OpenSSL 3.1: Support ends 2025-03-14.
-- - OpenSSL 3.2: Native Keccak support added.

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "Unsupported OpenSSL version. Please install OpenSSL >= 1.1.0"
#endif

-- -------------------------------------------------------------------------- --
--
-- Example for idiomatic use of OpenSSL message digests cf.
-- https://www.openssl.org/docs/man3.1/man7/crypto.html
--

-- -------------------------------------------------------------------------- --
-- Exceptions

newtype OpenSslException = OpenSslException String
    deriving (Show)

instance Exception OpenSslException

-- -------------------------------------------------------------------------- --
-- OpenSSL Message Digest Algorithms

-- | An algorithm implementation from an OpenSSL algorithm provider.
--
-- It must be freed after use. Internally, implementations are cached and
-- reference counted. Re-initialization after the last reference is freed is
-- somewhat expensive.
--
-- It is assumed that this always points to a valid algorithm implementation.
--
newtype Algorithm a = Algorithm (ForeignPtr Void)

instance Typeable a => Show (Algorithm a) where
    show _ = show (typeRep (Nothing @a))

class OpenSslDigest a where
    algorithm :: Algorithm a

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
-- | Fetches the digest implementation for the given algorithm from any provider
-- offering it, within the criteria given by the properties.
--
-- cf. https://www.openssl.org/docs/man3.0/man3/EVP_MD_fetch.html for details.
--
-- The obtained algorithm implementation is reference counted and must be freed
-- afer use.
--
-- The arguments are the OpenSSL context which is usually NULL, the algorithm
-- identifier, and the search criteria.
--
foreign import ccall unsafe "openssl/evp.h EVP_MD_fetch"
    c_evp_md_fetch :: Ptr Void {- nullPtr -} -> CString -> CString -> IO (Ptr a)

foreign import ccall unsafe "openssl/evp.h &EVP_MD_free"
    c_evp_md_free :: FunPtr (Ptr a -> IO ())

-- | Return an 'Algorithm' with given identifier from the default provider.
--
-- The result is guaranteed to be a valid algorithm. Otherwise an
-- 'OpenSslException' is thrown.
--
-- Cf. https://www.openssl.org/docs/manmaster/man7/OSSL_PROVIDER-default.html
-- for a list of available algorithms.
--
fetchAlgorithm :: String -> IO (Algorithm a)
fetchAlgorithm name = do
    withCString name $ \namePtr -> mask_ $ do
        ptr <- c_evp_md_fetch nullPtr namePtr (Ptr "provider=default"#)
        when (ptr == nullPtr) $ throw $ OpenSslException $ "fetching algorithm failed: " <> name
        Algorithm <$> newForeignPtr c_evp_md_free ptr
#else

foreign import ccall unsafe "openssl/evp.h EVP_get_digestbyname"
    c_EVP_get_digestbyname :: CString -> IO (Ptr a)

-- | Look up the 'Algorithm' with given identifier. This is a less efficient
-- legacy way to obtain algorithm implementations. The returned algorithms
-- do not need to be freed.
--
-- The result is guaranteed to be a valid algorithm. Otherwise an
-- 'OpenSslException' is thrown.
--
fetchAlgorithm :: String -> IO (Algorithm a)
fetchAlgorithm name = do
    withCString name $ \namePtr -> mask_ $ do
        ptr <- c_EVP_get_digestbyname namePtr
        when (ptr == nullPtr) $ throw $ OpenSslException $ "fetching algorithm failed: " <> name
        Algorithm <$> newForeignPtr_ ptr
#endif

-- -------------------------------------------------------------------------- --
-- Message Digest Context

-- | Generic OpenSSL message digest type.
--
-- This can be used with @DerivingVia@ to derive hash instances for concrete
-- message digest algorithms.
--
newtype Digest a = Digest BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString

-- | OpenSSL Message Digest Context
--
newtype Ctx a = Ctx (ForeignPtr Void)

-- | Initialize new MD context. The obtained context must be freed after use.
--
foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_new"
    c_evp_ctx_new :: IO (Ptr a)

foreign import ccall unsafe "openssl/evp.h &EVP_MD_CTX_free"
    c_evp_ctx_free_ptr :: FunPtr (Ptr a -> IO ())

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
foreign import ccall unsafe "openssl/evp.h EVP_DigestInit_ex2"
#else
foreign import ccall unsafe "openssl/evp.h EVP_DigestInit_ex"
#endif
    c_evp_digest_init :: Ptr ctx -> Ptr alg -> Ptr Void {- nullPtr -} -> IO Bool

foreign import ccall unsafe "openssl/evp.h EVP_DigestUpdate"
    c_evp_digest_update :: Ptr ctx -> Ptr d -> Int -> IO Bool

foreign import ccall unsafe "openssl/evp.h EVP_DigestFinal_ex"
    c_evp_digest_final :: Ptr ctx -> Ptr d -> Ptr Int -> IO Bool

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_get0_md"
#else
foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_md"
#endif
    c_evp_md_ctx_get0_md :: Ptr ctx -> Ptr a

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
foreign import ccall unsafe "openssl/evp.h EVP_MD_get_size"
#else
foreign import ccall unsafe "openssl/evp.h EVP_MD_size"
#endif
    c_evp_md_get_size :: Ptr a -> Int

newCtx :: IO (Ctx a)
newCtx = mask_ $ do
    ptr <- c_evp_ctx_new
    when (ptr == nullPtr) $ throw $ OpenSslException "failed to create new context"
    Ctx <$> newForeignPtr c_evp_ctx_free_ptr ptr
{-# INLINE newCtx #-}

-- | Allocates and initializes a new context. The context may be reused by
-- calling 'resetCtx' on it.
--
initCtx :: Algorithm a -> IO (Ctx a)
initCtx (Algorithm alg) = do
    c@(Ctx ctx) <- newCtx
    r <- withForeignPtr ctx $ \ctxPtr ->
        withForeignPtr alg $ \algPtr ->
            c_evp_digest_init ctxPtr algPtr nullPtr
    unless r $ throw $ OpenSslException "digest initialization failed"
    return c
{-# INLINE initCtx #-}

-- | Resets a context an initialize context.
--
resetCtx :: Ctx a -> IO ()
resetCtx (Ctx ctx) = do
    r <- withForeignPtr ctx $ \ptr ->
        c_evp_digest_init ptr nullPtr nullPtr
    unless r $ throw $ OpenSslException "digest re-initialization failed"
{-# INLINE resetCtx #-}

-- | Feed more data into an context.
--
updateCtx :: Ctx a -> Ptr Word8 -> Int -> IO ()
updateCtx (Ctx ctx) d c = withForeignPtr ctx $ \ptr -> do
    r <- c_evp_digest_update ptr d c
    unless r $ throw $ OpenSslException "digest update failed"
{-# INLINE updateCtx #-}

-- | Finalize a hash and return the digest.
--
finalCtx :: Ctx a -> IO (Digest a)
finalCtx (Ctx ctx) = withForeignPtr ctx $ \ptr -> do
    let s = c_evp_md_get_size (c_evp_md_ctx_get0_md ptr)
    allocaBytes s $ \dptr -> do
        r <- c_evp_digest_final ptr dptr nullPtr
        unless r $ throw $ OpenSslException "digest finalization failed"
        Digest <$> BS.packCStringLen (dptr, s)
{-# INLINE finalCtx #-}

-- -------------------------------------------------------------------------- --
-- Hash Instances for Digest

instance OpenSslDigest a => Hash (Digest a) where
    initialize = initCtx (algorithm @a)
    {-# INLINE initialize #-}

instance IncrementalHash (Digest a) where
    type Context (Digest a) = Ctx a
    update = updateCtx
    finalize = finalCtx
    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance ResetableHash (Digest a) where
    reset = resetCtx
    {-# INLINE reset #-}

-- -------------------------------------------------------------------------- --
-- Hashes based on extendable-output functions (XOF)

newtype XOF_Digest (n :: Natural) a = XOF_Digest BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Hash, ResetableHash) via (Digest a)
    deriving (Show, IsString) via B16ShortByteString

foreign import ccall unsafe "openssl/evp.h EVP_DigestFinalXOF"
    c_EVP_DigestFinalXOF :: Ptr ctx -> Ptr d -> Int -> IO Bool

-- | Finalize an XOF based hash and return the digest.
--
xof_finalCtx :: forall n a . KnownNat n => Ctx a -> IO (XOF_Digest n a)
xof_finalCtx (Ctx ctx) = withForeignPtr ctx $ \ptr -> do
    allocaBytes s $ \dptr -> do
        r <- c_EVP_DigestFinalXOF ptr dptr s
        unless r $ throw $ OpenSslException "digest finalization failed"
        XOF_Digest <$> BS.packCStringLen (dptr, s)
  where
    s = fromIntegral $ natVal' @n proxy#
{-# INLINE xof_finalCtx #-}

instance KnownNat n => IncrementalHash (XOF_Digest n a) where
    type Context (XOF_Digest n a) = Ctx a
    update = updateCtx
    finalize = xof_finalCtx
    {-# INLINE update #-}
    {-# INLINE finalize #-}

#if OPENSSL_VERSION_NUMBER < 0x30200000L
-- -------------------------------------------------------------------------- --
-- Legacy Keccak Implementation

newtype LegacyKeccak_Digest a = LegacyKeccak_Digest BS.ShortByteString
    deriving (Eq, Ord)
    deriving (IncrementalHash) via (Digest a)
    deriving (Show, IsString) via B16ShortByteString

foreign import ccall unsafe "keccak.h keccak_EVP_DigestInit_ex"
    c_keccak_EVP_DigestInit_ex :: Ptr ctx -> Ptr a -> IO Bool

legacyKeccak_initCtx :: Algorithm a -> IO (Ctx a)
legacyKeccak_initCtx (Algorithm alg) = do
    c@(Ctx ctx) <- newCtx
    r <- withForeignPtr ctx $ \ctxPtr ->
        withForeignPtr alg $ \algPtr ->
            c_keccak_EVP_DigestInit_ex ctxPtr algPtr
    unless r $ throw $ OpenSslException "digest initialization failed"
    return c
{-# INLINE legacyKeccak_initCtx #-}

legacyKeccak_resetCtx :: Ctx a -> IO ()
legacyKeccak_resetCtx (Ctx ctx) = do
    r <- withForeignPtr ctx $ \ptr ->
        c_keccak_EVP_DigestInit_ex ptr nullPtr
    unless r $ throw $ OpenSslException "digest re-initialization failed"
{-# INLINE legacyKeccak_resetCtx #-}

instance OpenSslDigest a => Hash (LegacyKeccak_Digest a) where
    initialize = legacyKeccak_initCtx (algorithm @a)
    {-# INLINE initialize #-}

instance ResetableHash (LegacyKeccak_Digest a) where
    reset = legacyKeccak_resetCtx
    {-# INLINE reset #-}
#endif

-- -------------------------------------------------------------------------- --
-- Concrete Digests
-- -------------------------------------------------------------------------- --

-- -------------------------------------------------------------------------- --
-- SHA-2

-- $sha2
--
-- SHA-2 (Secure Hash Algorithm 2) is a family of cryptographic hash functions
-- standardized in NIST FIPS 180-4, first published in 2001. These functions
-- conform to NIST FIPS 180-4.
--
-- The following hash functions from the SHA-2 family are supported in
-- openssl-3.0 (cf. https://www.openssl.org/docs/man3.0/man3/EVP_sha224.html)
--
-- SHA2-224, SHA2-256, SHA2-512/224, SHA2-512/256, SHA2-384, SHA2-512


-- OpenSSL < 3.0 uses legacy algorithm names. This should be replaced in the
-- code when the support for older versions of OpenSSL is removed.

sha2_224 :: Algorithm Sha2_224
sha2_224 = unsafePerformIO $ fetchAlgorithm "SHA224"
{-# NOINLINE sha2_224 #-}

sha2_256 :: Algorithm Sha2_256
sha2_256 = unsafePerformIO $ fetchAlgorithm "SHA256"
{-# NOINLINE sha2_256 #-}

sha2_384 :: Algorithm Sha2_384
sha2_384 = unsafePerformIO $ fetchAlgorithm "SHA384"
{-# NOINLINE sha2_384 #-}

sha2_512 :: Algorithm Sha2_512
sha2_512 = unsafePerformIO $ fetchAlgorithm "SHA512"
{-# NOINLINE sha2_512 #-}

sha2_512_224 :: Algorithm Sha2_512_224
sha2_512_224 = unsafePerformIO $ fetchAlgorithm "SHA512-224"
{-# NOINLINE sha2_512_224 #-}

sha2_512_256 :: Algorithm Sha2_512_256
sha2_512_256 = unsafePerformIO $ fetchAlgorithm "SHA512-256"
{-# NOINLINE sha2_512_256 #-}

newtype Sha2_224 = Sha2_224 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_224)
instance OpenSslDigest Sha2_224 where algorithm = sha2_224

newtype Sha2_256 = Sha2_256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_256)
instance OpenSslDigest Sha2_256 where algorithm = sha2_256

newtype Sha2_384 = Sha2_384 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_384)
instance OpenSslDigest Sha2_384 where algorithm = sha2_384

newtype Sha2_512 = Sha2_512 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_512)
instance OpenSslDigest Sha2_512 where algorithm = sha2_512

newtype Sha2_512_224 = Sha2_512_224 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_512_224)
instance OpenSslDigest Sha2_512_224 where algorithm = sha2_512_224

newtype Sha2_512_256 = Sha2_512_256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_512_256)
instance OpenSslDigest Sha2_512_256 where algorithm = sha2_512_256

-- -------------------------------------------------------------------------- --
-- SHA-3

-- $sha3
--
-- SHA-3 (Secure Hash Algorithm 3) is a family of cryptographic hash functions
-- standardized in NIST FIPS 202, first published in 2015. It is based on the
-- Keccak algorithm. These functions conform to NIST FIPS 202.
--
-- The following hash functions from the SHA-3 family are supported in
-- openssl-3.0 (cf. https://www.openssl.org/docs/man3.0/man3/EVP_sha3_224.html)
--
-- SHA3-3_224, SHA3-3_256, SHA3-3_384, SHA3-3_512, SHAKE128, SHAKE256

sha3_224 :: Algorithm Sha3_224
sha3_224 = unsafePerformIO $ fetchAlgorithm "SHA3-224"
{-# NOINLINE sha3_224 #-}

sha3_256 :: Algorithm Sha3_256
sha3_256 = unsafePerformIO $ fetchAlgorithm "SHA3-256"
{-# NOINLINE sha3_256 #-}

sha3_384 :: Algorithm Sha3_384
sha3_384 = unsafePerformIO $ fetchAlgorithm "SHA3-384"
{-# NOINLINE sha3_384 #-}

sha3_512 :: Algorithm Sha3_512
sha3_512 = unsafePerformIO $ fetchAlgorithm "SHA3-512"
{-# NOINLINE sha3_512 #-}

shake128 :: Algorithm (Shake128 n)
shake128 = unsafePerformIO $ fetchAlgorithm "SHAKE128"
{-# NOINLINE shake128 #-}

shake256 :: Algorithm (Shake256 n)
shake256 = unsafePerformIO $ fetchAlgorithm "SHAKE256"
{-# NOINLINE shake256 #-}

newtype Sha3_224 = Sha3_224 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha3_224)
instance OpenSslDigest Sha3_224 where algorithm = sha3_224

newtype Sha3_256 = Sha3_256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha3_256)
instance OpenSslDigest Sha3_256 where algorithm = sha3_256

newtype Sha3_384 = Sha3_384 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha3_384)
instance OpenSslDigest Sha3_384 where algorithm = sha3_384

newtype Sha3_512 = Sha3_512 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha3_512)
instance OpenSslDigest Sha3_512 where algorithm = sha3_512

newtype Shake128 (bits :: Natural) = Shake128 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (XOF_Digest bits (Shake128 bits))
instance OpenSslDigest (Shake128 n) where algorithm = shake128

newtype Shake256 (bits :: Natural) = Shake256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (XOF_Digest bits (Shake256 bits))
instance OpenSslDigest (Shake256 n) where algorithm = shake256

type Shake128_256 = Shake128 32
type Shake256_512 = Shake256 64

-- -------------------------------------------------------------------------- --
-- Keccak for OpenSSL >=3.2

-- $keccak
--
-- This is the latest version of Keccak-256 hash function that was submitted to
-- the SHA3 competition. It is different from the final NIST SHA3 hash.
--
-- The difference between NIST SHA3-256 and Keccak-256 is the use of a different
-- padding character for the input message. The former uses '0x06' and the
-- latter uses '0x01'.
--
-- This version of Keccak-256 is used by the Ethereum project.
--
-- The following hash functions from the SHA-3 family are supported in
-- openssl-3.2 (cf. https://www.openssl.org/docs/man3.2/man7/EVP_MD-KECCAK.html)
--
-- KECCAK-224, KECCAK-256, KECCAK-384, KECCAK-512
#if OPENSSL_VERSION_NUMBER < 0x30200000L
--
-- This implementation of Keccak-256 uses internal OpenSSL APIs. It may break
-- with new versions of OpenSSL. It may also be broken for existing versions of
-- OpenSSL. Portability of the code is unknown.
--
-- ONLY USE THIS CODE AFTER YOU HAVE VERIFIED THAT IT WORKS WITH OUR VERSION OF
-- OPENSSL.
--
-- For details see the file cbits/keccak.c.
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#define KECCAK(x) ("KECCAK-" <> show @Int x)
#define KECCAK_DIGEST Digest
#else
#define KECCAK(x) ("SHA3-" <> show @Int x)
#define KECCAK_DIGEST LegacyKeccak_Digest
#endif

keccak_224 :: Algorithm Keccak224
keccak_224 = unsafePerformIO $ fetchAlgorithm KECCAK(224)
{-# NOINLINE keccak_224 #-}

keccak_256 :: Algorithm Keccak256
keccak_256 = unsafePerformIO $ fetchAlgorithm KECCAK(256)
{-# NOINLINE keccak_256 #-}

keccak_384 :: Algorithm Keccak384
keccak_384 = unsafePerformIO $ fetchAlgorithm KECCAK(384)
{-# NOINLINE keccak_384 #-}

keccak_512 :: Algorithm Keccak512
keccak_512 = unsafePerformIO $ fetchAlgorithm KECCAK(512)
{-# NOINLINE keccak_512 #-}

newtype Keccak224 = Keccak224 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (KECCAK_DIGEST Keccak224)
instance OpenSslDigest Keccak224 where algorithm = keccak_224

newtype Keccak256 = Keccak256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (KECCAK_DIGEST Keccak256)
instance OpenSslDigest Keccak256 where algorithm = keccak_256

newtype Keccak384 = Keccak384 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (KECCAK_DIGEST Keccak384)
instance OpenSslDigest Keccak384 where algorithm = keccak_384

newtype Keccak512 = Keccak512 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (KECCAK_DIGEST Keccak512)
instance OpenSslDigest Keccak512 where algorithm = keccak_512

-- | Low-Level function that writes the final digest directly into the provided
-- pointer. The pointer must point to at least 64 bytes of allocated memory.
-- This is not checked and a violation of this condition may result in a
-- segmentation fault.
--
finalizeKeccak256Ptr :: Ctx Keccak256 -> Ptr Word8 -> IO ()
finalizeKeccak256Ptr (Ctx ctx) dptr =
    withForeignPtr ctx $ \cptr -> do
        r <- c_evp_digest_final cptr dptr nullPtr
        unless r $ throw $ OpenSslException "digest finalization failed"
{-# INLINE finalizeKeccak256Ptr #-}

-- | Low-Level function that writes the final digest directly into the provided
-- pointer. The pointer must point to at least 64 bytes of allocated memory.
-- This is not checked and a violation of this condition may result in a
-- segmentation fault.
--
finalizeKeccak512Ptr :: Ctx Keccak512 -> Ptr Word8 -> IO ()
finalizeKeccak512Ptr (Ctx ctx) dptr = do
    withForeignPtr ctx $ \cptr -> do
        r <- c_evp_digest_final cptr dptr nullPtr
        unless r $ throw $ OpenSslException "digest finalization failed"
{-# INLINE finalizeKeccak512Ptr #-}

-- -------------------------------------------------------------------------- --
-- Blake

-- $blake2
--
-- BLAKE2 is an improved version of BLAKE, which was submitted to the NIST SHA-3
-- algorithm competition. The BLAKE2s and BLAKE2b algorithms are described in
-- RFC 7693.
--
-- The following hash functions from the BLAKE2 family are supported in
-- openssl-3.0 (cf.
-- https://www.openssl.org/docs/man3.0/man3/EVP_blake2b512.html)
--
-- BLAKE2B-512, BLACKE2S-256
--
-- While the BLAKE2b and BLAKE2s algorithms supports a variable length digest,
-- this implementation outputs a digest of a fixed length (the maximum length
-- supported), which is 512-bits for BLAKE2b and 256-bits for BLAKE2s.

blake2b512 :: Algorithm Blake2b512
blake2b512 = unsafePerformIO $ fetchAlgorithm "BLAKE2b512"
{-# NOINLINE blake2b512 #-}

blake2s256 :: Algorithm Blake2s256
blake2s256 = unsafePerformIO $ fetchAlgorithm "BLAKE2s256"
{-# NOINLINE blake2s256 #-}

newtype Blake2b512 = Blake2b512 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Blake2b512)
instance OpenSslDigest Blake2b512 where algorithm = blake2b512

newtype Blake2s256 = Blake2s256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Blake2s256)
instance OpenSslDigest Blake2s256 where algorithm = blake2s256

