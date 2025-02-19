{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE UnliftedFFITypes #-}

#if !MIN_VERSION_base(4,18,0)
{-# LANGUAGE PatternSynonyms #-}
#endif

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
, updateCtxPtr
, updateCtx#
, finalCtxPtr
, finalCtx#
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

-- ** Blake2
--
-- $blake2

, Blake2b512(..)
, Blake2s256(..)
) where

import Control.Exception
import Control.Monad

import Data.Array.Byte
import Data.ByteString.Short qualified as BS
import Data.Typeable
import Data.Void
import Data.Word

#if MIN_VERSION_base(4,18,0)
import Foreign.C.ConstPtr (ConstPtr(..))
import Foreign.C.String (withCString)
#else
import Foreign.C.String(CString, withCString)
#endif
import Foreign.C.Types
import Foreign.ForeignPtr
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
-- Utils for ConstPtr

#if MIN_VERSION_base(4,18,0)
type ConstCString = ConstPtr CChar
#else
type ConstPtr a = Ptr a
type ConstCString = CString

pattern ConstPtr :: forall p. p -> p
pattern ConstPtr a = a
#endif

withConstCString :: String -> (ConstCString -> IO a) -> IO a
withConstCString str inner = withCString str $ \cstr -> inner (ConstPtr cstr)

constPtr :: Addr# -> ConstPtr a
constPtr a = ConstPtr (Ptr a)

nullConstPtr :: ConstPtr a
nullConstPtr = ConstPtr nullPtr

-- -------------------------------------------------------------------------- --
-- Misc utils

toCSize# :: Int# -> CSize
toCSize# i# = fromIntegral (I# i#)

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
newtype Algorithm a = Algorithm (ForeignPtr a)

instance Typeable a => Show (Algorithm a) where
    show _ = show (typeRep (Nothing @a))

class KnownNat (OpenSslDigestSize a) => OpenSslDigest a where
    type OpenSslDigestSize a :: Natural
    algorithm :: Algorithm a

openSslDigestSize :: forall a n . OpenSslDigest a => Num n => n
openSslDigestSize = fromIntegral $ natVal' @(OpenSslDigestSize a) proxy#

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
    c_evp_md_fetch :: Ptr Void {- nullPtr -} -> ConstCString -> ConstCString -> IO (Ptr a)

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
    withConstCString name $ \namePtr -> mask_ $ do
        ptr <- c_evp_md_fetch nullPtr namePtr (constPtr "provider=default"#)
        when (ptr == nullPtr) $ throw $ OpenSslException $ "fetching algorithm failed: " <> name
        Algorithm <$> newForeignPtr c_evp_md_free ptr
#else

foreign import ccall unsafe "openssl/evp.h EVP_get_digestbyname"
    c_EVP_get_digestbyname :: ConstCString -> IO (ConstPtr a)

-- | Look up the 'Algorithm' with given identifier. This is a less efficient
-- legacy way to obtain algorithm implementations. The returned algorithms
-- do not need to be freed.
--
-- The result is guaranteed to be a valid algorithm. Otherwise an
-- 'OpenSslException' is thrown.
--
fetchAlgorithm :: String -> IO (Algorithm a)
fetchAlgorithm name = do
    withConstCString name $ \namePtr -> mask_ $ do
        ConstPtr ptr <- c_EVP_get_digestbyname namePtr
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
newtype Digest a = Digest ByteArray
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
    c_evp_digest_init :: Ptr ctx -> ConstPtr alg -> Ptr Void {- nullPtr -} -> IO CInt

foreign import ccall unsafe "openssl/evp.h EVP_DigestUpdate"
    c_evp_digest_update_ptr :: Ptr ctx -> ConstPtr d -> CSize -> IO CInt

foreign import capi unsafe "evp_wrapper.h EVP_DigestUpdate_off"
    c_evp_digest_update_off :: Ptr ctx -> ByteArray# -> CSize -> CSize -> IO CInt

foreign import ccall unsafe "openssl/evp.h EVP_DigestFinal_ex"
    c_evp_digest_final_ptr :: Ptr ctx -> Ptr CUChar -> Ptr CUInt -> IO CInt

foreign import capi unsafe "evp_wrapper.h EVP_DigestFinal_ex_off"
    c_evp_digest_final_off :: Ptr ctx -> MutableByteArray# RealWorld -> CSize -> Ptr CUInt -> IO CInt

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
foreign import ccall unsafe "openssl/evp.h EVP_MD_get_size"
#else
foreign import ccall unsafe "openssl/evp.h EVP_MD_size"
#endif
    c_evp_md_get_size :: ConstPtr a -> CInt

-- | Assert the correct output size for the context.
--
-- NOTE that for OpenSSL <3.4 the output for XOF digests is size that
-- corresponds to the security of the algorithm.
--
-- Starting with OpenSSL 3.4 the output for XOF digests is 0.
--
assertAlgorithmDigestSize :: forall a . OpenSslDigest a => (Ptr a) -> IO ()
assertAlgorithmDigestSize algPtr =
    unless (mdSize == 0 || mdSize == algSize) $ throw $ OpenSslException $
        "failed to create new context for output size " <> show algSize
            <> ". The algorithm offers " <> show mdSize
  where
    mdSize = fromIntegral @_ @Int $ c_evp_md_get_size (ConstPtr algPtr)
    algSize = openSslDigestSize @a

newCtx :: forall a . IO (Ctx a)
newCtx = mask_ $ do
    ptr <- c_evp_ctx_new
    when (ptr == nullPtr) $ throw $ OpenSslException "failed to create new context"
    Ctx <$> newForeignPtr c_evp_ctx_free_ptr ptr
{-# INLINE newCtx #-}

-- | Allocates and initializes a new context. The context may be reused by
-- calling 'resetCtx' on it.
--
initCtx :: forall a . OpenSslDigest a => Algorithm a -> IO (Ctx a)
initCtx (Algorithm alg) = do
    c@(Ctx ctx) <- newCtx
    r <- withForeignPtr ctx $ \ctxPtr ->
        withForeignPtr alg $ \algPtr -> do
            assertAlgorithmDigestSize algPtr
            c_evp_digest_init ctxPtr (ConstPtr algPtr) nullPtr
    when (r == 0) $ throw $ OpenSslException "digest initialization failed"
    return c
{-# INLINE initCtx #-}

-- | Resets a context an initialize context.
--
resetCtx :: Ctx a -> IO ()
resetCtx (Ctx ctx) = do
    r <- withForeignPtr ctx $ \ptr ->
        c_evp_digest_init ptr nullConstPtr nullPtr
    when (r == 0) $ throw $ OpenSslException "digest re-initialization failed"
{-# INLINE resetCtx #-}

-- | Feed more data into an context.
--
updateCtxPtr :: Ctx a -> Ptr Word8 -> Int -> IO ()
updateCtxPtr (Ctx ctx) d c = withForeignPtr ctx $ \ptr -> do
    r <- c_evp_digest_update_ptr ptr (ConstPtr d) (fromIntegral c)
    when (r == 0) $ throw $ OpenSslException "digest update failed"
{-# INLINE updateCtxPtr #-}

-- | Feed more data into an context from an possibly unpinned ByteArray without
-- copying the content.
--
updateCtx# :: Ctx a -> ByteArray# -> Int# -> Int# -> IO ()
updateCtx# (Ctx ctx) arr# off# len# = withForeignPtr ctx $ \ptr -> do
    when (isTrue# (size# <# off# +# len#)) $
        throwIO $ OpenSslException "input array to small"
    r <- c_evp_digest_update_off ptr arr# (toCSize# off#) (toCSize# len#)
    when (r == 0) $ throw $ OpenSslException "digest update failed"
  where
    size# = sizeofByteArray# arr#
{-# INLINE updateCtx# #-}

-- | Finalize a hash and return the digest.
--
finalCtx#
    :: forall a
    . OpenSslDigest a
    => Ctx a
    -> MutableByteArray# RealWorld
    -> Int#
    -> IO ()
finalCtx# (Ctx ctx) arr# off# = withForeignPtr ctx $ \ptr -> do

    -- When this is called from the default implementation of final this check
    -- is redundant. But I guess it is cheap enough to worry about it.
    asize <- IO $ \s -> case getSizeofMutableByteArray# arr# s of
            (# s', n# #) -> (# s', I# (n# -# off#) #)
    when (asize < openSslDigestSize @a) $
        throwIO $ OpenSslException "array to small for digest"

    r <- c_evp_digest_final_off ptr arr# (toCSize# off#) nullPtr
    when (r == 0) $ throwIO $ OpenSslException "digest finalization failed"
{-# INLINE finalCtx# #-}

finalCtxPtr :: Ctx a -> Ptr Word8 -> IO ()
finalCtxPtr (Ctx ctx) dptr =
    withForeignPtr ctx $ \cptr -> do
        r <- c_evp_digest_final_ptr cptr (castPtr dptr) nullPtr
        when (r == 0) $ throw $ OpenSslException "digest finalization failed"
{-# INLINE finalCtxPtr #-}

-- -------------------------------------------------------------------------- --
-- Hash Instances for Digest

instance OpenSslDigest a => Hash (Digest a) where
    initialize = initCtx (algorithm @a)
    {-# INLINE initialize #-}

instance (OpenSslDigest a) => IncrementalHash (Digest a) where
    type Context (Digest a) = Ctx a
    type DigestSize (Digest a) = OpenSslDigestSize a
    updatePtr = updateCtxPtr
    update# = updateCtx#
    finalize# = finalCtx#
    finalizePtr = finalCtxPtr
    {-# INLINE updatePtr #-}
    {-# INLINE finalize# #-}

instance OpenSslDigest a => ResetableHash (Digest a) where
    reset = resetCtx
    {-# INLINE reset #-}

-- -------------------------------------------------------------------------- --
-- Hashes based on extendable-output functions (XOF)

newtype XOF_Digest a = XOF_Digest ByteArray
    deriving (Eq, Ord)
    deriving (ResetableHash) via (Digest a)
    deriving (Show, IsString) via B16ShortByteString

#if OPENSSL_VERSION_NUMBER < 0x30400000L
-- | For OpenSSL <3.4 this implementation skips the assertion of the output
-- digest size for XOF digests.
--
instance OpenSslDigest a => Hash (XOF_Digest a) where
    initialize = xof_initCtx (algorithm @a)
    {-# INLINE initialize #-}

-- | Allocates and initializes a new context. The context may be reused by
-- calling 'resetCtx' on it.
--
-- This is the same as 'initCtx' but omits the assertion of the output digest
-- size.
--
xof_initCtx :: forall a . OpenSslDigest a => Algorithm a -> IO (Ctx a)
xof_initCtx (Algorithm alg) = do
    c@(Ctx ctx) <- newCtx
    r <- withForeignPtr ctx $ \ctxPtr ->
        withForeignPtr alg $ \algPtr -> do
            c_evp_digest_init ctxPtr (ConstPtr algPtr) nullPtr
    when (r == 0) $ throw $ OpenSslException "digest initialization failed"
    return c
{-# INLINE xof_initCtx #-}
#else
deriving via (Digest a) instance OpenSslDigest a => Hash (XOF_Digest a)
#endif

foreign import ccall unsafe "openssl/evp.h EVP_DigestFinalXOF"
    c_EVP_DigestFinalXOF_ptr :: Ptr ctx -> Ptr CUChar -> CSize -> IO CInt

foreign import capi unsafe "evp_wrapper.h EVP_DigestFinalXOF_off"
    c_EVP_DigestFinalXOF_off :: Ptr ctx -> MutableByteArray# s -> CSize -> CSize -> IO CInt

-- | Finalize an XOF based hash and return the digest.
--
xof_finalCtx#
    :: forall a
    . OpenSslDigest a
    => Ctx a
    -> MutableByteArray# RealWorld
    -> Int#
    -> IO ()
xof_finalCtx# (Ctx ctx) arr# off# = withForeignPtr ctx $ \ptr -> do

    -- When this is called from the default implementation of final this check
    -- is redundant. But I guess it is cheap enough to worry about it.
    asize <- IO $ \s -> case getSizeofMutableByteArray# arr# s of
            (# s', n# #) -> (# s', I# (n# -# off#) #)
    when (asize < openSslDigestSize @a) $
        throwIO $ OpenSslException "array to small for digest"

    r <- c_EVP_DigestFinalXOF_off ptr arr# (toCSize# off#) (openSslDigestSize @a)
    when (r == 0) $ throwIO $ OpenSslException "digest finalization failed"
{-# INLINE xof_finalCtx# #-}

xof_finalCtxPtr :: forall a . OpenSslDigest a => Ctx a -> Ptr Word8 -> IO ()
xof_finalCtxPtr (Ctx ctx) dptr =
    withForeignPtr ctx $ \cptr -> do
        r <- c_EVP_DigestFinalXOF_ptr cptr (castPtr dptr) (openSslDigestSize @a)
        when (r == 0) $ throw $ OpenSslException "digest finalization failed"
{-# INLINE xof_finalCtxPtr #-}

instance OpenSslDigest a => IncrementalHash (XOF_Digest a) where
    type Context (XOF_Digest a) = Ctx a
    type DigestSize (XOF_Digest a) = OpenSslDigestSize a
    updatePtr = updateCtxPtr
    update# = updateCtx#
    finalize# = xof_finalCtx#
    finalizePtr = xof_finalCtxPtr
    {-# INLINE updatePtr #-}
    {-# INLINE finalize# #-}
    {-# INLINE finalizePtr #-}

#if OPENSSL_VERSION_NUMBER < 0x30200000L
-- -------------------------------------------------------------------------- --
-- Legacy Keccak Implementation

newtype LegacyKeccak_Digest a = LegacyKeccak_Digest ByteArray
    deriving (Eq, Ord)
    deriving (IncrementalHash) via (Digest a)
    deriving (Show, IsString) via B16ShortByteString

foreign import ccall unsafe "keccak.h keccak_EVP_DigestInit_ex"
    c_keccak_EVP_DigestInit_ex :: Ptr ctx -> ConstPtr a -> IO CInt

legacyKeccak_initCtx :: Algorithm a -> IO (Ctx a)
legacyKeccak_initCtx (Algorithm alg) = do
    c@(Ctx ctx) <- newCtx
    r <- withForeignPtr ctx $ \ctxPtr ->
        withForeignPtr alg $ \algPtr ->
            c_keccak_EVP_DigestInit_ex ctxPtr (ConstPtr algPtr)
    when (r == 0) $ throw $ OpenSslException "digest initialization failed"
    return c
{-# INLINE legacyKeccak_initCtx #-}

legacyKeccak_resetCtx :: Ctx a -> IO ()
legacyKeccak_resetCtx (Ctx ctx) = do
    r <- withForeignPtr ctx $ \ptr ->
        c_keccak_EVP_DigestInit_ex ptr nullConstPtr
    when (r == 0) $ throw $ OpenSslException "digest re-initialization failed"
{-# INLINE legacyKeccak_resetCtx #-}

instance OpenSslDigest a => Hash (LegacyKeccak_Digest a) where
    initialize = legacyKeccak_initCtx (algorithm @a)
    {-# INLINE initialize #-}

instance OpenSslDigest a => ResetableHash (LegacyKeccak_Digest a) where
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

newtype Sha2_224 = Sha2_224 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_224)
instance OpenSslDigest Sha2_224 where
    type OpenSslDigestSize Sha2_224 = 28
    algorithm = sha2_224

newtype Sha2_256 = Sha2_256 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_256)
instance OpenSslDigest Sha2_256 where
    type OpenSslDigestSize Sha2_256 = 32
    algorithm = sha2_256

newtype Sha2_384 = Sha2_384 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_384)
instance OpenSslDigest Sha2_384 where
    type OpenSslDigestSize Sha2_384 = 48
    algorithm = sha2_384

newtype Sha2_512 = Sha2_512 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_512)
instance OpenSslDigest Sha2_512 where
    type OpenSslDigestSize Sha2_512 = 64
    algorithm = sha2_512

newtype Sha2_512_224 = Sha2_512_224 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_512_224)
instance OpenSslDigest Sha2_512_224 where
    type OpenSslDigestSize Sha2_512_224 = 28
    algorithm = sha2_512_224

newtype Sha2_512_256 = Sha2_512_256 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha2_512_256)
instance OpenSslDigest Sha2_512_256 where
    type OpenSslDigestSize Sha2_512_256 = 32
    algorithm = sha2_512_256

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

newtype Sha3_224 = Sha3_224 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha3_224)
instance OpenSslDigest Sha3_224 where
    type OpenSslDigestSize Sha3_224 = 28
    algorithm = sha3_224

newtype Sha3_256 = Sha3_256 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha3_256)
instance OpenSslDigest Sha3_256 where
    type OpenSslDigestSize Sha3_256 = 32
    algorithm = sha3_256

newtype Sha3_384 = Sha3_384 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha3_384)
instance OpenSslDigest Sha3_384 where
    type OpenSslDigestSize Sha3_384 = 48
    algorithm = sha3_384

newtype Sha3_512 = Sha3_512 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Sha3_512)
instance OpenSslDigest Sha3_512 where
    type OpenSslDigestSize Sha3_512 = 64
    algorithm = sha3_512

newtype Shake128 (n :: Natural) = Shake128 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (XOF_Digest (Shake128 n))
instance KnownNat n => OpenSslDigest (Shake128 n) where
    type OpenSslDigestSize (Shake128 n) = n
    algorithm = shake128

newtype Shake256 (n :: Natural) = Shake256 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (XOF_Digest (Shake256 n))
instance KnownNat n => OpenSslDigest (Shake256 n) where
    type OpenSslDigestSize (Shake256 n) = n
    algorithm = shake256

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

newtype Keccak224 = Keccak224 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (KECCAK_DIGEST Keccak224)
instance OpenSslDigest Keccak224 where
    type OpenSslDigestSize Keccak224 = 28
    algorithm = keccak_224

newtype Keccak256 = Keccak256 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (KECCAK_DIGEST Keccak256)
instance OpenSslDigest Keccak256 where
    type OpenSslDigestSize Keccak256 = 32
    algorithm = keccak_256

newtype Keccak384 = Keccak384 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (KECCAK_DIGEST Keccak384)
instance OpenSslDigest Keccak384 where
    type OpenSslDigestSize Keccak384 = 48
    algorithm = keccak_384

newtype Keccak512 = Keccak512 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (KECCAK_DIGEST Keccak512)
instance OpenSslDigest Keccak512 where
    type OpenSslDigestSize Keccak512 = 64
    algorithm = keccak_512

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

newtype Blake2b512 = Blake2b512 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Blake2b512)
instance OpenSslDigest Blake2b512 where
    type OpenSslDigestSize Blake2b512 = 64
    algorithm = blake2b512

newtype Blake2s256 = Blake2s256 ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString
    deriving (IncrementalHash, Hash, ResetableHash) via (Digest Blake2s256)
instance OpenSslDigest Blake2s256 where
    type OpenSslDigestSize Blake2s256 = 32
    algorithm = blake2s256

