{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Main
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Main
( main
) where

import Control.Monad

import Criterion
import Criterion.Main

#if defined(BENCHMARK_CRYPTONITE)
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Hash as BA
import qualified Crypto.Hash as C
#endif

#if defined(WITH_OPENSSL)
import Data.Coerce
#endif

#if defined(BENCHMARK_CRYPTONITE) || defined(WITH_OPENSSL)
import qualified Data.ByteString.Short as BS
#endif

import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import Data.Word

import GHC.Ptr

import System.IO.Unsafe

-- internal modules

import qualified Data.Hash.SipHash as SH
import qualified Data.Hash.FNV1 as FH

#if defined(WITH_OPENSSL)
import qualified Data.Hash.Class.Mutable as H
import qualified Data.Hash.SHA3 as SHA3
import qualified Data.Hash.SHA2 as SHA2
import qualified Data.Hash.Blake2 as BLAKE2
import qualified Data.Hash.Keccak as K
#endif

-- -------------------------------------------------------------------------- --
-- Main

main :: IO ()
main = do
    defaultMain
        [ bgroup "sipHash" $ []
            <> [runBench "internal" (internalSipHash 17 17)]
#if defined(BENCHMARK_CRYPTONITE)
            <> [runBench "memory" (memorySipHash 17 17)]
#endif

        , bgroup "fnv1aHash" $ []
            <> [runBench "internal" internalFnv1a]
            <> [runBench "primitive" primitiveFnv1a]
#if defined(BENCHMARK_CRYPTONITE)
            <> [runBench "memory" memoryFnv1a]
#endif

        , bgroup "Sha2_256" $ []
#if defined(WITH_OPENSSL)
            <> [runBench "openssl" (ossl @SHA2.Sha2_256)]
#endif
#if defined(BENCHMARK_CRYPTONITE)
            <> [runBench "cryptonite" (cryptonite @C.SHA256)]
#endif

        , bgroup "Sha2_512" $ []
#if defined(WITH_OPENSSL)
            <> [runBench "openssl" (ossl @SHA2.Sha2_512)]
#endif
#if defined(BENCHMARK_CRYPTONITE)
            <> [runBench "cryptonite" (cryptonite @C.SHA512)]
#endif

        , bgroup "Sha3_256" $ []
#if defined(WITH_OPENSSL)
            <> [runBench "openssl" (ossl @SHA3.Sha3_256)]
#endif
#if defined(BENCHMARK_CRYPTONITE)
            <> [runBench "cryptonite" (cryptonite @C.SHA3_256)]
#endif

        , bgroup "Sha3_512" $ []
#if defined(WITH_OPENSSL)
            <> [runBench "openssl" (ossl @SHA3.Sha3_512)]
#endif
#if defined(BENCHMARK_CRYPTONITE)
            <> [runBench "cryptonite" (cryptonite @C.SHA3_512)]
#endif

        , bgroup "keccak256" $ []
#if defined(WITH_OPENSSL)
            <> [runBench "openssl" (ossl @K.Keccak256)]
#endif
#if defined(BENCHMARK_CRYPTONITE)
            <> [runBench "cryptonite" (cryptonite @C.Keccak_256)]
#endif
        , bgroup "keccak512" $ []
#if defined(WITH_OPENSSL)
            <> [runBench "openssl" (ossl @K.Keccak512)]
#endif
#if defined(BENCHMARK_CRYPTONITE)
            <> [runBench "cryptonite" (cryptonite @C.Keccak_512)]
#endif

        , bgroup "blake2s256" $ []
#if defined(WITH_OPENSSL)
            <> [ runBench "openssl" (ossl @BLAKE2.Blake2s256) ]
#endif
#if defined(BENCHMARK_CRYPTONITE)
            <> [runBench "cryptonite" (cryptonite @C.Blake2s_256)]
#endif

        , bgroup "blake2b512" $ []
#if defined(WITH_OPENSSL)
            <> [ runBench "openssl" (ossl @BLAKE2.Blake2b512) ]
#endif
#if defined(BENCHMARK_CRYPTONITE)
            <> [ runBench "cryptonite" (cryptonite @C.Blake2b_512) ]
#endif
        ]

-- -------------------------------------------------------------------------- --
-- Benchmark Runner

runBench :: String -> (B.ByteString -> a) -> Benchmark
runBench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

benchStrings :: [B.ByteString]
benchStrings = str <$> [0, 1, 5, 67, 300, 2000, 20000]
  where
    str (i :: Int) = B.pack $ fromIntegral <$> [0..i-1]

#if defined(BENCHMARK_CRYPTONITE)
cryptonite :: forall a . C.HashAlgorithm a => B.ByteString -> BS.ShortByteString
cryptonite b = BS.toShort $ BA.convert $! C.hash @_ @a b
{-# INLINE cryptonite #-}
#endif

#if defined(WITH_OPENSSL)
ossl :: forall a . Coercible a BS.ShortByteString => H.Hash a => B.ByteString -> BS.ShortByteString
ossl b = coerce $! SHA3.hashByteString_ @a b
{-# INLINE ossl #-}
#endif

-- -------------------------------------------------------------------------- --
-- SipHash

#if defined(BENCHMARK_CRYPTONITE)
memorySipHash :: BA.ByteArrayAccess p => Word64 -> Word64 -> p -> Word64
memorySipHash w0 w1 x = r
  where
    BA.SipHash r = BA.sipHash (BA.SipKey w0 w1) x
{-# INLINE memorySipHash #-}
#endif

internalSipHash :: Word64 -> Word64 -> B.ByteString -> Word64
internalSipHash w0 w1 x = r
  where
    SH.SipHash r = SH.hashByteString @(SH.SipHash 2 4) (SH.SipHashKey w0 w1) x
{-# INLINE internalSipHash #-}

-- -------------------------------------------------------------------------- --
-- Fvn1Hash

#if defined(BENCHMARK_CRYPTONITE)
memoryFnv1a :: B.ByteString -> Word64
memoryFnv1a b = h
  where
    BA.FnvHash64 h = BA.fnv1a_64Hash b
{-# INLINE memoryFnv1a #-}
#endif

internalFnv1a :: B.ByteString -> Word64
internalFnv1a b = r
  where
    FH.Fnv1a64Hash r = FH.hashByteString @FH.Fnv1a64Hash b
{-# INLINE internalFnv1a #-}

primitiveFnv1a :: B.ByteString -> Word64
primitiveFnv1a b = unsafeDupablePerformIO $
    B.unsafeUseAsCStringLen b $ \(addr, n) ->
        fromIntegral <$!> FH.fnv1a_host (castPtr addr) n
{-# INLINE primitiveFnv1a #-}

