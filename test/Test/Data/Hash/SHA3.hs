{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Test.Data.Hash.SHA3
-- Copyright: Copyright © 2022 Kadena LLC.
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

import Test.Syd
import Test.Hash.SHA3

-- internal modules

import Data.Hash.SHA2
import Data.Hash.SHA3

-- -------------------------------------------------------------------------- --
--

tests :: Spec
tests = describe "SHA3 Test Vectors" $ do
    shortMsgTests
    longMsgTests
    monteTests

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

