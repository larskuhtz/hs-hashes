{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

#include <openssl/opensslv.h>

-- |
-- Module: Data.Hash.Internal.OpenSSL
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Bindings for OpenSSL EVP Message Digest Routines
--
module Data.Hash.Internal.OpenSSL
(

-- * EVP digest routines

  Algorithm(..)
, Ctx(..)
, Digest(..)
, newCtx
, initCtx
, updateCtx
, finalCtx

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
, Shake256(..)

-- ** Keccak
--
-- $keccak

, Keccak256(..)

-- ** Blake2
--
-- $blake2

, Blake2b512(..)
, Blake2s256(..)
) where

import Control.Exception
import Control.Monad

import qualified Data.ByteString.Short as BS
import Data.Void
import Data.Word

import Foreign.ForeignPtr
import Foreign.Marshal
import Foreign.Ptr

import GHC.IO

-- internal modules

import Data.Hash.Class.Mutable
import Data.Hash.Internal.Utils


#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "Unsupported OpenSSL version. Please install OpenSSL >= 1.1.0"
#endif

-- -------------------------------------------------------------------------- --
-- OpenSSL Message Digests

newtype OpenSslException = OpenSslException String
    deriving (Show)

instance Exception OpenSslException

newtype Algorithm = Algorithm (Ptr Void)
newtype Ctx a = Ctx (ForeignPtr Void)
newtype Digest a = Digest BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_new"
#else
foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_create"
#endif
    c_evp_ctx_new :: IO (Ptr a)

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
foreign import ccall unsafe "openssl/evp.h &EVP_MD_CTX_free"
#else
foreign import ccall unsafe "openssl/evp.h &EVP_MD_CTX_destroy"
#endif
    c_evp_ctx_free_ptr :: FunPtr (Ptr a -> IO ())

-- obsolete, superseeded by EVP_DigestInit_ex instead, but not deprecated
-- (beware in case this becomes a macro in future versions)
--
foreign import ccall unsafe "opnessl/evp.h EVP_DigestInit"
    c_evp_digest_init :: Ptr ctx -> Ptr alg -> IO Bool

foreign import ccall unsafe "opnessl/evp.h EVP_DigestUpdate"
    c_evp_digest_update :: Ptr ctx -> Ptr d -> Int -> IO Bool

foreign import ccall unsafe "opnessl/evp.h EVP_DigestFinal"
    c_evp_digest_final :: Ptr ctx -> Ptr d -> Int -> IO Bool

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_get0_md"
#else
foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_md"
#endif
    c_evp_ctx_get0_md :: Ptr ctx -> IO Algorithm

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
foreign import ccall unsafe "openssl/evp.h EVP_MD_get_size"
#else
foreign import ccall unsafe "openssl/evp.h EVP_MD_size"
#endif
    c_evp_get_size :: Algorithm -> IO Int

newCtx :: IO (Ctx a)
newCtx = fmap Ctx $ mask_ $ do
    ptr <- c_evp_ctx_new
    when (ptr == nullPtr) $ throw $ OpenSslException "failed to initialize context"
    newForeignPtr c_evp_ctx_free_ptr ptr
{-# INLINE newCtx #-}

initCtx :: Algorithm -> IO (Ctx a)
initCtx (Algorithm alg) = do
    Ctx ctx <- newCtx
    r <- withForeignPtr ctx $ \ptr ->
        c_evp_digest_init ptr alg
    unless r $ throw $ OpenSslException "digest initialization failed"
    return $ Ctx ctx
{-# INLINE initCtx #-}

updateCtx :: Ctx a -> Ptr Word8 -> Int -> IO ()
updateCtx (Ctx ctx) d c = withForeignPtr ctx $ \ptr -> do
    r <- c_evp_digest_update ptr d c
    unless r $ throw $ OpenSslException "digest update failed"
{-# INLINE updateCtx #-}

finalCtx :: Ctx a -> IO (Digest a)
finalCtx (Ctx ctx) = withForeignPtr ctx $ \ptr -> do
    s <- c_evp_ctx_get0_md ptr >>= c_evp_get_size
    allocaBytes s $ \dptr -> do
        r <- c_evp_digest_final ptr dptr 0
        unless r $ throw $ OpenSslException "digest finalization failed"
        Digest <$> BS.packCStringLen (dptr, s)
{-# INLINE finalCtx #-}

-- -------------------------------------------------------------------------- --
-- Support for DerivingVia

class OpenSslDigest a where
    algorithm :: Algorithm

instance OpenSslDigest a => IncrementalHash (Digest a) where
    type Context (Digest a) = Ctx a
    update = updateCtx
    finalize = finalCtx
    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance OpenSslDigest a => Hash (Digest a) where
    initialize = initCtx (algorithm @a)
    {-# INLINE initialize #-}

-- -------------------------------------------------------------------------- --
-- Digests
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
-- EVP_sha224, EVP_sha256, EVP_sha512_224, EVP_sha512_256, EVP_sha384,
-- EVP_sha512
--

foreign import ccall unsafe "openssl/evp.h EVP_sha224"
    c_evp_sha2_224 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_sha256"
    c_evp_sha2_256 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_sha384"
    c_evp_sha2_384 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_sha512"
    c_evp_sha2_512 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_sha512_224"
    c_evp_sha2_512_224 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_sha512_256"
    c_evp_sha2_512_256 :: Algorithm

newtype Sha2_224 = Sha2_224 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha2_224)
instance OpenSslDigest Sha2_224 where algorithm = c_evp_sha2_224

newtype Sha2_256 = Sha2_256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha2_256)
instance OpenSslDigest Sha2_256 where algorithm = c_evp_sha2_256

newtype Sha2_384 = Sha2_384 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha2_384)
instance OpenSslDigest Sha2_384 where algorithm = c_evp_sha2_384

newtype Sha2_512 = Sha2_512 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha2_512)
instance OpenSslDigest Sha2_512 where algorithm = c_evp_sha2_512

newtype Sha2_512_224 = Sha2_512_224 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha2_512_224)
instance OpenSslDigest Sha2_512_224 where algorithm = c_evp_sha2_512_224

newtype Sha2_512_256 = Sha2_512_256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha2_512_256)
instance OpenSslDigest Sha2_512_256 where algorithm = c_evp_sha2_512_256

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
-- EVP_sha3_224, EVP_sha3_256, EVP_sha3_384, EVP_sha3_512, EVP_shake128,
-- EVP_shake256

foreign import ccall unsafe "openssl/evp.h EVP_sha3_224"
    c_evp_sha3_224 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_sha3_256"
    c_evp_sha3_256 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_sha3_384"
    c_evp_sha3_384 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_sha3_512"
    c_evp_sha3_512 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_shake128"
    c_evp_shake128 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_shake256"
    c_evp_shake256 :: Algorithm

newtype Sha3_224 = Sha3_224 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha3_224)
instance OpenSslDigest Sha3_224 where algorithm = c_evp_sha3_224

newtype Sha3_256 = Sha3_256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha3_256)
instance OpenSslDigest Sha3_256 where algorithm = c_evp_sha3_256

newtype Sha3_384 = Sha3_384 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha3_384)
instance OpenSslDigest Sha3_384 where algorithm = c_evp_sha3_384

newtype Sha3_512 = Sha3_512 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Sha3_512)
instance OpenSslDigest Sha3_512 where algorithm = c_evp_sha3_512

newtype Shake128 = Shake128 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Shake128)
instance OpenSslDigest Shake128 where algorithm = c_evp_shake128

newtype Shake256 = Shake256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Shake256)
instance OpenSslDigest Shake256 where algorithm = c_evp_shake256

-- -------------------------------------------------------------------------- --
-- Keccak

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
-- This implementation of Keccak-256 uses internal OpenSSL APIs. It may break
-- with new versions of OpenSSL. It may also be broken for existing versions of
-- OpenSSL. Portability of the code is unknown.
--
-- ONLY USE THIS CODE AFTER YOU HAVE VERIFIED THAT IT WORKS WITH OUR VERSION OF
-- OPENSSL.
--
-- For details see the file cbits/keccak.c.

newtype Keccak256 = Keccak256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString

foreign import ccall unsafe "keccak.h keccak256_newctx"
    c_keccak256_newctx :: IO (Ptr ctx)

foreign import ccall unsafe "keccak.h keccak256_init"
    c_keccak256_init :: Ptr ctx -> IO Bool

foreign import ccall unsafe "keccak.h keccak256_update"
    c_keccak256_update :: Ptr ctx -> Ptr Word8 -> Int -> IO Bool

foreign import ccall unsafe "keccak.h keccak256_final"
    c_keccak256_final :: Ptr ctx -> Ptr Word8 -> IO Bool

foreign import ccall unsafe "keccak.h &keccak256_freectx"
    c_keccak256_freectx_ptr :: FunPtr (Ptr ctx -> IO ())

instance IncrementalHash Keccak256 where
    type Context Keccak256 = Ctx Keccak256
    update (Ctx ctx) ptr n = withForeignPtr ctx $ \cptr -> do
        r <- c_keccak256_update cptr ptr n
        unless r $ throw $ OpenSslException "digest update failed"
    finalize (Ctx ctx) = withForeignPtr ctx $ \cptr -> do
        allocaBytes 32 $ \dptr -> do
            r <- c_keccak256_final cptr dptr
            unless r $ throw $ OpenSslException "digest finalization failed"
            Keccak256 <$> BS.packCStringLen (castPtr dptr, 32)
    {-# INLINE update #-}
    {-# INLINE finalize #-}


newKeccak256Ctx :: IO (Ctx Keccak256)
newKeccak256Ctx = fmap Ctx $ mask_ $ do
    ptr <- c_keccak256_newctx
    when (ptr == nullPtr) $ throw $ OpenSslException "failed to initialize context"
    newForeignPtr c_keccak256_freectx_ptr ptr
{-# INLINE newKeccak256Ctx #-}

instance Hash Keccak256 where
    initialize = do
        Ctx ctx <- newKeccak256Ctx
        r <- withForeignPtr ctx $ \ptr ->
            c_keccak256_init ptr
        unless r $ throw $ OpenSslException "digest initialization failed"
        return $ Ctx ctx
    {-# INLINE initialize #-}

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
-- EVP_blake2b512, EVP_blake2s256
--
-- While the BLAKE2b and BLAKE2s algorithms supports a variable length digest,
-- this implementation outputs a digest of a fixed length (the maximum length
-- supported), which is 512-bits for BLAKE2b and 256-bits for BLAKE2s.
--
--

foreign import ccall unsafe "openssl/evp.h EVP_blake2b512"
    c_evp_blake2b512 :: Algorithm

foreign import ccall unsafe "openssl/evp.h EVP_blake2s256"
    c_evp_blake2s256 :: Algorithm

newtype Blake2b512 = Blake2b512 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Blake2b512)
instance OpenSslDigest Blake2b512 where algorithm = c_evp_blake2b512

newtype Blake2s256 = Blake2s256 BS.ShortByteString
    deriving (Eq, Ord)
    deriving (Show) via B16ShortByteString
    deriving (IncrementalHash, Hash) via (Digest Blake2s256)
instance OpenSslDigest Blake2s256 where algorithm = c_evp_blake2s256

