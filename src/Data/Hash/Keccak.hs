{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Data.Hash.Keccak
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- | The code in this module uses internal OpenSSL APIs. It may break with new
-- versions of OpenSSL. Portability of the code is unknown.
--
-- ONLY USE THIS CODE AFTER YOU HAVE VERIFIED THAT IT WORKS WITH OUR VERSION OF
-- OPENSSL.
--
-- Allocation of memory for the context is potentially fragile. The value used
-- below is based on the following code:
--
-- https://github.com/openssl/openssl/blob/1c0eede9827b0962f1d752fa4ab5d436fa039da4/include/internal/sha3.h#L34
--
-- @
-- # define KECCAK1600_WIDTH 1600
-- # define SHA3_MDSIZE(bitlen)    (bitlen / 8)
-- # define KMAC_MDSIZE(bitlen)    2 * (bitlen / 8)
-- # define SHA3_BLOCKSIZE(bitlen) (KECCAK1600_WIDTH - bitlen * 2) / 8
--
-- typedef struct keccak_st KECCAK1600_CTX;
--
-- typedef size_t (sha3_absorb_fn)(void *vctx, const void *inp, size_t len);
-- typedef int (sha3_final_fn)(unsigned char *md, void *vctx);
--
-- typedef struct prov_sha3_meth_st
-- {
--     sha3_absorb_fn *absorb;
--     sha3_final_fn *final;
-- } PROV_SHA3_METHOD;
--
-- struct keccak_st {
--     uint64_t A[5][5];
--     size_t block_size;          /* cached ctx->digest->block_size */
--     size_t md_size;             /* output length, variable in XOF */
--     size_t bufsz;               /* used bytes in below buffer */
--     unsigned char buf[KECCAK1600_WIDTH / 8 - 32];
--     unsigned char pad;
--     PROV_SHA3_METHOD meth;
-- };
-- @
--
-- Assumeing a word size of 64bit we get \(5*5*8 + 8 + 8 + 8 + 168 + 1 + 16 = 409\).
-- We round up to the next multiple of 8 and get 416.
--
--
module Data.Hash.Keccak
( Keccak256Hash(..)
, Keccak256Context
, keccakInitialize
, keccakUpdate
, keccakFinalize
, module Data.Hash.Class.Mutable
) where

import Control.Exception
import Control.Monad

import qualified Data.ByteString.Short as BS
import Data.Word

import Foreign.ForeignPtr
import Foreign.Marshal
import Foreign.Ptr

import GHC.Stack

import Text.Printf

-- internal modules

import Data.Hash.Class.Mutable
import Data.Hash.Internal.OpenSSL (OpenSslException(..))

-- -------------------------------------------------------------------------- --
-- Keccak 256 Hash

newtype Keccak256Hash = Keccak256Hash BS.ShortByteString
    deriving (Eq, Ord)

instance Show Keccak256Hash where
    show (Keccak256Hash b) = concatMap (printf "%0.2X") $ BS.unpack b

newtype Keccak256Context = Keccak256Context (ForeignPtr Word8)

-- -------------------------------------------------------------------------- --
-- OpenSSL

-- int ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned char pad, size_t bitlen)
foreign import ccall unsafe "internal/sha3.h ossl_sha3_init"
    c_ossl_sha3_init :: Ptr ctx -> Word8 -> Int -> IO Bool

-- int ossl_sha3_update(KECCAK1600_CTX *ctx, const void *_inp, size_t len)
foreign import ccall unsafe "internal/sha3.h ossl_sha3_update"
    c_ossl_sha3_update :: Ptr ctx -> Ptr Word8 -> Int -> IO Bool

-- int ossl_sha3_final(unsigned char *md, KECCAK1600_CTX *ctx)
foreign import ccall unsafe "internal/sha3.h ossl_sha3_final"
    c_ossl_sha3_final :: Ptr Word8 -> Ptr ctx -> IO Bool

keccakInitialize :: HasCallStack => IO Keccak256Context
keccakInitialize = do
    bytes <- mallocForeignPtrBytes 416 -- cf. above
    r <- withForeignPtr bytes $ \ptr -> c_ossl_sha3_init ptr 0x1 256
    unless r $ throw $ OpenSslException "keccakInitialize: failed to initialize KECCAK1600_CTX"
    return $ Keccak256Context bytes
{-# INLINE keccakInitialize #-}

keccakUpdate :: Keccak256Context -> Ptr a -> Int -> IO ()
keccakUpdate (Keccak256Context ctx) ptr n = do
    r <- withForeignPtr ctx $ \ctxPtr -> c_ossl_sha3_update ctxPtr (castPtr ptr) n
    unless r $ throw $ OpenSslException "keccakUpdate: failed to update KECCAK1600_CTX"
{-# INLINE keccakUpdate #-}

keccakFinalize :: Keccak256Context -> IO Keccak256Hash
keccakFinalize (Keccak256Context ctx) = allocaBytes 32 $ \ptr -> do
    r <- withForeignPtr ctx $ \ctxPtr -> c_ossl_sha3_final ptr ctxPtr
    unless r $ throw $ OpenSslException "keccakFinalize: failed to finalize KECCAK1600_CTX"
    Keccak256Hash <$> BS.packCStringLen (castPtr ptr, 32)
{-# INLINE keccakFinalize #-}

-- -------------------------------------------------------------------------- --
-- Instances

instance IncrementalHash Keccak256Hash where
    type Context Keccak256Hash = Keccak256Context
    update = keccakUpdate
    finalize = keccakFinalize
    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance Hash Keccak256Hash where
    initialize = keccakInitialize
    {-# INLINE initialize #-}

