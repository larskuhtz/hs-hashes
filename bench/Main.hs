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

import Criterion
import Criterion.Main

#ifdef BENCHMARK_MEMORY
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Hash as BA
#endif
import qualified Data.ByteString as B
import Data.Word

import Test.QuickCheck

-- internal modules

import qualified Data.Hash.SipHash as SH
import qualified Data.Hash.FNV1 as FH

-- -------------------------------------------------------------------------- --
-- Main

main :: IO ()
main = do
#ifdef BENCHMARK_MEMORY
    putStrLn "prop_sip"
    quickCheck prop_sip
    putStrLn "prop_fnv1a"
    quickCheck prop_fnv1a
#endif
    putStrLn "prop_fnv1aPrimitive"
    quickCheck prop_fnv1aPrimitive
    defaultMain
        [ bgroup "sipHash"
            [ sipBench "internal" (internalSipHash 17 17)
#ifdef BENCHMARK_MEMORY
            , sipBench "memory" (memorySipHash 17 17)
#endif
            ]
        , bgroup "fnv1aHash"
            [ fnv1aBench "internal" internalFnv1a
            , fnv1aBench "primitive" primitiveFnv1a
#ifdef BENCHMARK_MEMORY
            , fnv1aBench "memory" memoryFnv1a
#endif
            ]
        ]

-- -------------------------------------------------------------------------- --
-- SipHash

#ifdef BENCHMARK_MEMORY
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

#ifdef BENCHMARK_MEMORY
prop_sip :: Word64 -> Word64 -> [Word8] -> Property
prop_sip w0 w1 b =
    memorySipHash w0 w1 (B.pack b) === internalSipHash w0 w1 (B.pack b)
#endif

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

#ifdef BENCHMARK_MEMORY
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
primitiveFnv1a b = fromIntegral r
  where
    FH.Fnv1aHash r = FH.hashByteString @FH.Fnv1aHash b
{-# INLINE primitiveFnv1a #-}

#ifdef BENCHMARK_MEMORY
prop_fnv1a :: [Word8] -> Property
prop_fnv1a b = memoryFnv1a (B.pack b) === internalFnv1a (B.pack b)
#endif

prop_fnv1aPrimitive :: [Word8] -> Property
prop_fnv1aPrimitive b = primitiveFnv1a (B.pack b) === internalFnv1a (B.pack b)

fnv1aBench :: String -> (B.ByteString -> Word64) -> Benchmark
fnv1aBench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

