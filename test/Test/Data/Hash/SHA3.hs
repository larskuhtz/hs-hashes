{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Test.Data.Hash.SHA3
-- Copyright: Copyright © 2022-2024 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
-- Test with test vectors from the
-- [NIST Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#Testing).
--
-- For details about the test proceedure cf. https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
--
-- The test data (response files) are provided by the
-- [sha-validation package](https://hackage.haskell.org/package/sha-validation).
--
module Test.Data.Hash.SHA3
( tests
) where

import qualified Data.ByteString.Short as BS
import Data.Coerce

import Test.Hspec
import Test.Hash.SHA3

-- internal modules

import Data.Hash.SHA3
import Data.Hash.Internal.Utils

-- -------------------------------------------------------------------------- --

tests :: Spec
tests = describe "SHA3 Test Vectors" $ do
    trivial
    shortMsgTests
    longMsgTests
    monteTests

-- -------------------------------------------------------------------------- --
-- Trivial Tests

trivial :: Spec
trivial = describe "trivial hashes" $ do

    go @Sha3_224 "224" "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    go @Sha3_256 "256" "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    go @Sha3_384 "384" "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    go @Sha3_512 "512" "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    go @Shake128_256 "Shake128_256" "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    go @Shake256_512 "shake256_512" "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
  where
    go
        :: forall a
        . Hash a
        => Eq a
        => Show a
        => Coercible a B16ShortByteString
        => String
        -> a
        -> Spec
    go l b = do
        it l $ shouldBe (hashShortByteString_ @a "") b


-- -------------------------------------------------------------------------- --
-- Msg Tests

shortMsgTests :: Spec
shortMsgTests = describe "ShortMsg" $ do
    describe "224" $ runMsgTest @Sha3_224 sha3_224ShortMsg
    describe "256" $ runMsgTest @Sha3_256 sha3_256ShortMsg
    describe "384" $ runMsgTest @Sha3_384 sha3_384ShortMsg
    describe "512" $ runMsgTest @Sha3_512 sha3_512ShortMsg

longMsgTests :: Spec
longMsgTests = describe "LongMsg" $ do
    describe "224" $ runMsgTest @Sha3_224 sha3_224LongMsg
    describe "256" $ runMsgTest @Sha3_256 sha3_256LongMsg
    describe "384" $ runMsgTest @Sha3_384 sha3_384LongMsg
    describe "512" $ runMsgTest @Sha3_512 sha3_512LongMsg

runMsgTest
    :: forall a
    . Hash a
    => Coercible a BS.ShortByteString
    => MsgFile
    -> Spec
runMsgTest = msgAssert
    (\l a b -> it l (a == b))
    (BS.fromShort . coerce . hashByteString_ @a)

-- -------------------------------------------------------------------------- --
-- Monte Tests

monteTests :: Spec
monteTests = describe "Monte" $ do
    describe "224" $ runMonteTest @Sha3_224 sha3_224Monte
    describe "256" $ runMonteTest @Sha3_256 sha3_256Monte
    describe "384" $ runMonteTest @Sha3_384 sha3_384Monte
    describe "512" $ runMonteTest @Sha3_512 sha3_512Monte

runMonteTest
    :: forall a
    . Hash a
    => Coercible a BS.ShortByteString
    => MonteFile
    -> Spec
runMonteTest = monteAssert
    (\l a b -> it l (a == b))
    (BS.fromShort . coerce . hashByteString_ @a)

