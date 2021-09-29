{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

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

import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Hash as BA
import qualified Data.ByteString as B
import Data.Word

import GHC.Ptr

import Test.QuickCheck

-- internal modules

import qualified Data.Hash.SipHash as H
import qualified Data.Hash.FNV1 as H

-- -------------------------------------------------------------------------- --
-- Main

main :: IO ()
main = do
    putStrLn "prop_sip"
    quickCheck prop_sip
    putStrLn "prop_fnv1a"
    quickCheck prop_fnv1a
    putStrLn "prop_fnv1aPrimitive"
    quickCheck prop_fnv1aPrimitive
    defaultMain
        [ bgroup "sipHash"
            [ sipBench "memory" (memorySipHash 17 17)
            , sipBench "internal" (H.hashByteString $ H.sipHash24 17 17)
            ]
        , bgroup "fnv1aHash"
            [ fnv1aBench "memory" memoryFnv1a
            , fnv1aBench "internal" (H.hashByteString H.fnv1a_64)
            , fnv1aBench "primitive" primitiveFnv1a
            ]
        ]

-- -------------------------------------------------------------------------- --
-- SipHash

memorySipHash :: BA.ByteArrayAccess p => Word64 -> Word64 -> p -> Word64
memorySipHash w0 w1 x = let BA.SipHash r = BA.sipHash (BA.SipKey w0 w1) x in r
{-# INLINE memorySipHash #-}

prop_sip :: Word64 -> Word64 -> [Word8] -> Property
prop_sip w0 w1 b =
    memorySipHash w0 w1 (B.pack b) === H.hashByteString (H.sipHash24 w0 w1) (B.pack b)

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

memoryFnv1a :: B.ByteString -> Word64
memoryFnv1a b = let BA.FnvHash64 h = BA.fnv1a_64Hash b in h
{-# INLINE memoryFnv1a #-}

primitiveFnv1a :: B.ByteString -> Word64
primitiveFnv1a = H.hashByteString $ \(Ptr addr) n ->
    fromIntegral <$> H.fnv1a addr n
{-# INLINE primitiveFnv1a #-}

prop_fnv1a :: [Word8] -> Property
prop_fnv1a b = memoryFnv1a (B.pack b) === H.hashByteString H.fnv1a_64 (B.pack b)

prop_fnv1aPrimitive :: [Word8] -> Property
prop_fnv1aPrimitive b = primitiveFnv1a (B.pack b) === H.hashByteString H.fnv1a_64 (B.pack b)

fnv1aBench :: String -> (B.ByteString -> Word64) -> Benchmark
fnv1aBench l f = bgroup l $ go <$> benchStrings
  where
    go i = bench (show (B.length i)) $ whnf f i

