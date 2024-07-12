{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Cryptonite
-- Copyright: Copyright © 2021-2024 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Compatibility with Cryptonite
--
module Cryptonite
( run
, tests
) where

import Control.Monad

#if defined(WITH_OPENSSL)
import qualified Crypto.Hash as C
import qualified Data.ByteArray as BA
import qualified Data.ByteString.Short as BS
import Data.Coerce
#endif

import qualified Data.ByteArray.Hash as BA
import qualified Data.ByteString as B
import Data.Word

import Test.QuickCheck
import Test.Syd

-- internal modules

#if defined(WITH_OPENSSL)
import Data.Hash.SHA2
import Data.Hash.SHA3
import Data.Hash.Blake2
import Data.Hash.Keccak
import qualified Data.Hash.Class.Mutable as M
#endif

import qualified Data.Hash.SipHash as SH
import qualified Data.Hash.FNV1 as FH

-- -------------------------------------------------------------------------- --
-- OpenSSL

run :: IO ()
run = forM_ properties $ \(n, t) -> do
    putStrLn $ "cryptonite compatiblity for " <> n
    quickCheck t

tests :: Spec
tests = mapM_ (uncurry prop) properties

#if defined(WITH_OPENSSL)
prop_eq
    :: forall alg calg
    . Coercible BS.ShortByteString alg
    => C.HashAlgorithm calg
    => M.Hash alg
    => [Word8]
    -> Property
prop_eq b = internal === cryptonite
  where
    bytes = B.pack b
    cryptonite = BS.toShort $ BA.convert $ C.hash @_ @calg bytes
    internal = coerce $ M.hashByteString_ @alg bytes
#endif

-- -------------------------------------------------------------------------- --
-- SipHash

-- | Compare with SipHash from the memory package
--
prop_eq_sip :: Word64 -> Word64 -> [Word8] -> Property
prop_eq_sip w0 w1 b = internal === memory
  where
    bytes = B.pack b
    SH.SipHash internal = SH.hashByteString @(SH.SipHash 2 4) (SH.SipHashKey w0 w1) bytes
    BA.SipHash memory = BA.sipHash (BA.SipKey w0 w1) bytes

-- -------------------------------------------------------------------------- --
-- Fvn1Hash

prop_eq_fnv132 :: [Word8] -> Property
prop_eq_fnv132 b = internal === memory
  where
    bytes = B.pack b
    FH.Fnv132Hash internal = FH.hashByteString @FH.Fnv132Hash bytes
    BA.FnvHash32 memory = BA.fnv1Hash bytes

prop_eq_fnv164 :: [Word8] -> Property
prop_eq_fnv164 b = internal === memory
  where
    bytes = B.pack b
    FH.Fnv164Hash internal = FH.hashByteString @FH.Fnv164Hash bytes
    BA.FnvHash64 memory = BA.fnv1_64Hash bytes

-- FIXME: assumes x_64
prop_eq_fnv1Host :: [Word8] -> Property
prop_eq_fnv1Host b = fromIntegral internal64 === internalHost
  where
    bytes = B.pack b
    FH.Fnv164Hash internal64 = FH.hashByteString @FH.Fnv164Hash bytes
    FH.Fnv1Hash internalHost = FH.hashByteString @FH.Fnv1Hash bytes

prop_eq_fnv1a32 :: [Word8] -> Property
prop_eq_fnv1a32 b = internal === memory
  where
    bytes = B.pack b
    FH.Fnv1a32Hash internal = FH.hashByteString @FH.Fnv1a32Hash bytes
    BA.FnvHash32 memory = BA.fnv1aHash bytes

prop_eq_fnv1a64 :: [Word8] -> Property
prop_eq_fnv1a64 b = internal === memory
  where
    bytes = B.pack b
    FH.Fnv1a64Hash internal = FH.hashByteString @FH.Fnv1a64Hash bytes
    BA.FnvHash64 memory = BA.fnv1a_64Hash bytes

-- FIXME: assumes x_64
prop_eq_fnv1aHost :: [Word8] -> Property
prop_eq_fnv1aHost b = fromIntegral internal64 === internalHost
  where
    bytes = B.pack b
    FH.Fnv1a64Hash internal64 = FH.hashByteString @FH.Fnv1a64Hash bytes
    FH.Fnv1aHash internalHost = FH.hashByteString @FH.Fnv1aHash bytes

-- -------------------------------------------------------------------------- --
-- Tests

properties :: [(String, Property)]
properties =
    [ ("prop_eq_sip", property prop_eq_sip)
    , ("prop_eq_fnv132", property prop_eq_fnv132)
    , ("prop_eq_fnv164", property prop_eq_fnv164)
    , ("prop_eq_fnv1Host", property prop_eq_fnv1Host)
    , ("prop_eq_fnv1a32", property prop_eq_fnv1a32)
    , ("prop_eq_fnv1a64", property prop_eq_fnv1a64)
    , ("prop_eq_fnv1aHost", property prop_eq_fnv1aHost)
#if defined(WITH_OPENSSL)
    , ("SHA2_224", property $ prop_eq @Sha2_224 @C.SHA224)
    , ("SHA2_256", property $ prop_eq @Sha2_256 @C.SHA256)
    , ("SHA2_384", property $ prop_eq @Sha2_384 @C.SHA384)
    , ("SHA2_512", property $ prop_eq @Sha2_512 @C.SHA512)
    , ("SHA2_512_224", property $ prop_eq @Sha2_512_224 @C.SHA512t_224)
    , ("SHA2_512_256", property $ prop_eq @Sha2_512_256 @C.SHA512t_256)
    , ("SHA3_224", property $ prop_eq @Sha3_224 @C.SHA3_224)
    , ("SHA3_256", property $ prop_eq @Sha3_256 @C.SHA3_256)
    , ("SHA3_384", property $ prop_eq @Sha3_384 @C.SHA3_384)
    , ("SHA3_512", property $ prop_eq @Sha3_512 @C.SHA3_512)
    , ("Blake2s256", property $ prop_eq @Blake2s256 @C.Blake2s_256)
    , ("Blake2b512", property $ prop_eq @Blake2b512 @C.Blake2b_512)
    , ("Keccak256", property $ prop_eq @Keccak256 @C.Keccak_256)
    , ("Keccak512", property $ prop_eq @Keccak512 @C.Keccak_512)
#endif
    ]

