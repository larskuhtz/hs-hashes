{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
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
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Short as BS
import Data.Word

import GHC.Ptr

import System.IO.Unsafe

-- internal modules

import qualified Data.Hash.SipHash as SH
import qualified Data.Hash.FNV1 as FH

#if defined(WITH_OPENSSL)
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
        [ bgroup "sipHash"
            [ sipBench "internal" (internalSipHash 17 17)
#if defined(BENCHMARK_CRYPTONITE)
            , sipBench "memory" (memorySipHash 17 17)
#endif
            ]

        , bgroup "fnv1aHash"
            [ fnv1aBench "internal" internalFnv1a
            , fnv1aBench "primitive" primitiveFnv1a
#if defined(BENCHMARK_CRYPTONITE)
            , fnv1aBench "memory" memoryFnv1a
#endif
            ]
        , bgroup "Sha2_256"
            [
#if defined(WITH_OPENSSL)
              sha2_256Bench "openssl" sha2_256Ssl
#endif
#if defined(BENCHMARK_CRYPTONITE)
            , sha2_256Bench "cryptonite" cryptoniteSha2_256
#endif
            ]

        , bgroup "Sha2_512"
            [
#if defined(WITH_OPENSSL)
              sha2_512Bench "openssl" sha2_512Ssl
#endif
#if defined(BENCHMARK_CRYPTONITE)
            , sha2_512Bench "cryptonite" cryptoniteSha2_512
#endif
            ]

        , bgroup "Sha3_256"
            [
#if defined(WITH_OPENSSL)
              sha3_256Bench "openssl" sha3_256Ssl
#endif
#if defined(BENCHMARK_CRYPTONITE)
            , sha3_256Bench "cryptonite" cryptoniteSha3_256
#endif
            ]

        , bgroup "Sha3_512"
            [
#if defined(WITH_OPENSSL)
              sha3_512Bench "openssl" sha3_512Ssl
#endif
#if defined(BENCHMARK_CRYPTONITE)
            , sha3_512Bench "cryptonite" cryptoniteSha3_512
#endif
            ]

        , bgroup "keccak256"
            [
#if defined(WITH_OPENSSL)
              keccakBench "openssl" keccak256Ssl
#endif
#if defined(BENCHMARK_CRYPTONITE)
            , keccakBench "cryptonite" cryptoniteKeccak256
#endif
            ]

        , bgroup "blake2s256"
            [
#if defined(WITH_OPENSSL)
              blake2s256Bench "openssl" blake2s256Ssl
#endif
#if defined(BENCHMARK_CRYPTONITE)
            , blake2s256Bench "cryptonite" cryptoniteBlake2s256
#endif
            ]

        , bgroup "blake2b512"
            [
#if defined(WITH_OPENSSL)
              blake2b512Bench "openssl" blake2b512Ssl
#endif
#if defined(BENCHMARK_CRYPTONITE)
            , blake2b512Bench "cryptonite" cryptoniteBlake2b512
#endif
            ]
        ]

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

sipBench :: String -> (B.ByteString -> Word64) -> Benchmark
sipBench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

benchStrings :: [B.ByteString]
benchStrings = str <$> [0, 1, 5, 67, 300, 2000, 20000]
  where
    str (i :: Int) = B.pack $ fromIntegral <$> [0..i-1]

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

fnv1aBench :: String -> (B.ByteString -> Word64) -> Benchmark
fnv1aBench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

-- -------------------------------------------------------------------------- --
-- SHA3 256

#if defined(WITH_OPENSSL)
sha3_256Ssl :: B.ByteString -> BS.ShortByteString
sha3_256Ssl b = r
  where
    SHA3.Sha3_256  r = SHA3.hashByteString @SHA3.Sha3_256 b
{-# INLINE sha3_256Ssl #-}
#endif

#if defined(BENCHMARK_CRYPTONITE)
cryptoniteSha3_256 :: B.ByteString -> BS.ShortByteString
cryptoniteSha3_256 b = BS.toShort $ BA.convert $! C.hash @_ @C.SHA3_256 b
{-# INLINE cryptoniteSha3_256 #-}
#endif

sha3_256Bench :: String -> (B.ByteString -> BS.ShortByteString) -> Benchmark
sha3_256Bench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

-- -------------------------------------------------------------------------- --
-- SHA3 512

#if defined(WITH_OPENSSL)
sha3_512Ssl :: B.ByteString -> BS.ShortByteString
sha3_512Ssl b = r
  where
    SHA3.Sha3_512  r = SHA3.hashByteString @SHA3.Sha3_512 b
{-# INLINE sha3_512Ssl #-}
#endif

#if defined(BENCHMARK_CRYPTONITE)
cryptoniteSha3_512 :: B.ByteString -> BS.ShortByteString
cryptoniteSha3_512 b = BS.toShort $ BA.convert $! C.hash @_ @C.SHA3_512 b
{-# INLINE cryptoniteSha3_512 #-}
#endif

sha3_512Bench :: String -> (B.ByteString -> BS.ShortByteString) -> Benchmark
sha3_512Bench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

-- -------------------------------------------------------------------------- --
-- SHA2_256

#if defined(WITH_OPENSSL)
sha2_256Ssl :: B.ByteString -> BS.ShortByteString
sha2_256Ssl b = r
  where
    SHA2.Sha2_256  r = SHA3.hashByteString @SHA2.Sha2_256 b
{-# INLINE sha2_256Ssl #-}
#endif

#if defined(BENCHMARK_CRYPTONITE)
cryptoniteSha2_256 :: B.ByteString -> BS.ShortByteString
cryptoniteSha2_256 b = BS.toShort $ BA.convert $! C.hash @_ @C.SHA256 b
{-# INLINE cryptoniteSha2_256 #-}
#endif

sha2_256Bench :: String -> (B.ByteString -> BS.ShortByteString) -> Benchmark
sha2_256Bench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

-- -------------------------------------------------------------------------- --
-- SHA2_512

#if defined(WITH_OPENSSL)
sha2_512Ssl :: B.ByteString -> BS.ShortByteString
sha2_512Ssl b = r
  where
    SHA2.Sha2_512  r = SHA3.hashByteString @SHA2.Sha2_512 b
{-# INLINE sha2_512Ssl #-}
#endif

#if defined(BENCHMARK_CRYPTONITE)
cryptoniteSha2_512 :: B.ByteString -> BS.ShortByteString
cryptoniteSha2_512 b = BS.toShort $ BA.convert $! C.hash @_ @C.SHA512 b
{-# INLINE cryptoniteSha2_512 #-}
#endif

sha2_512Bench :: String -> (B.ByteString -> BS.ShortByteString) -> Benchmark
sha2_512Bench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

-- -------------------------------------------------------------------------- --
-- BLAKE2B512

#if defined(WITH_OPENSSL)
blake2b512Ssl :: B.ByteString -> BS.ShortByteString
blake2b512Ssl b = r
  where
    BLAKE2.Blake2b512  r = BLAKE2.hashByteString @BLAKE2.Blake2b512 b
{-# INLINE blake2b512Ssl #-}
#endif

#if defined(BENCHMARK_CRYPTONITE)
cryptoniteBlake2b512 :: B.ByteString -> BS.ShortByteString
cryptoniteBlake2b512 b = BS.toShort $ BA.convert $! C.hash @_ @C.Blake2b_512 b
{-# INLINE cryptoniteBlake2b512 #-}
#endif

blake2b512Bench :: String -> (B.ByteString -> BS.ShortByteString) -> Benchmark
blake2b512Bench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

-- -------------------------------------------------------------------------- --
-- BLAKE2S256

#if defined(WITH_OPENSSL)
blake2s256Ssl :: B.ByteString -> BS.ShortByteString
blake2s256Ssl b = r
  where
    BLAKE2.Blake2s256  r = BLAKE2.hashByteString @BLAKE2.Blake2s256 b
{-# INLINE blake2s256Ssl #-}
#endif

#if defined(BENCHMARK_CRYPTONITE)
cryptoniteBlake2s256 :: B.ByteString -> BS.ShortByteString
cryptoniteBlake2s256 b = BS.toShort $ BA.convert $! C.hash @_ @C.Blake2s_256 b
{-# INLINE cryptoniteBlake2s256 #-}
#endif

blake2s256Bench :: String -> (B.ByteString -> BS.ShortByteString) -> Benchmark
blake2s256Bench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

-- -------------------------------------------------------------------------- --
-- Keccak 256

#if defined(WITH_OPENSSL)
keccak256Ssl :: B.ByteString -> BS.ShortByteString
keccak256Ssl b = r
  where
    K.Keccak256Hash  r = K.hashByteString @K.Keccak256Hash b
{-# INLINE keccak256Ssl #-}
#endif

#if defined(BENCHMARK_CRYPTONITE)
cryptoniteKeccak256 :: B.ByteString -> BS.ShortByteString
cryptoniteKeccak256 b = BS.toShort $ BA.convert $! C.hash @_ @C.Keccak_256 b
{-# INLINE cryptoniteKeccak256 #-}
#endif

keccakBench :: String -> (B.ByteString -> BS.ShortByteString) -> Benchmark
keccakBench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

