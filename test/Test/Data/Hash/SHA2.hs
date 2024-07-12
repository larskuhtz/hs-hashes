{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Test.Data.Hash.SHA2
-- Copyright: Copyright © 2024 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
-- Test with test vectors from the
-- [NIST Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#Testing).
--
-- For details about the test proceedure cf. https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/shs/shavs.pdf.
--
-- The test data (response files) are provided by the
-- [sha-validation package](https://hackage.haskell.org/package/sha-validation).
--
module Test.Data.Hash.SHA2
( tests
) where

import qualified Data.ByteString.Short as BS
import Data.Coerce

import Test.Syd
import Test.Hash.SHA

-- internal modules

import Data.Hash.SHA2

-- -------------------------------------------------------------------------- --
--

tests :: Spec
tests = describe "SHA2 Test Vectors" $ do
    shortMsgTests
    longMsgTests
    monteTests

-- -------------------------------------------------------------------------- --
-- NIST Msg Tests

shortMsgTests :: Spec
shortMsgTests = describe "ShortMsg" $ do
    describe "224" $ runMsgTest @Sha2_224 sha224ShortMsg
    describe "256" $ runMsgTest @Sha2_256 sha256ShortMsg
    describe "384" $ runMsgTest @Sha2_384 sha384ShortMsg
    describe "512" $ runMsgTest @Sha2_512 sha512ShortMsg
    describe "512_224" $ runMsgTest @Sha2_512_224 sha512_224ShortMsg
    describe "512_256" $ runMsgTest @Sha2_512_256 sha512_256ShortMsg

longMsgTests :: Spec
longMsgTests = describe "LongMsg" $ do
    describe "224" $ runMsgTest @Sha2_224 sha224LongMsg
    describe "256" $ runMsgTest @Sha2_256 sha256LongMsg
    describe "384" $ runMsgTest @Sha2_384 sha384LongMsg
    describe "512" $ runMsgTest @Sha2_512 sha512LongMsg
    describe "512_224" $ runMsgTest @Sha2_512_224 sha512_224LongMsg
    describe "512_256" $ runMsgTest @Sha2_512_256 sha512_256LongMsg

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
    describe "224" $ runMonteTest @Sha2_224 sha224Monte
    describe "256" $ runMonteTest @Sha2_256 sha256Monte
    describe "384" $ runMonteTest @Sha2_384 sha384Monte
    describe "512" $ runMonteTest @Sha2_512 sha512Monte
    describe "512_224" $ runMonteTest @Sha2_512_224 sha512_224Monte
    describe "512_256" $ runMonteTest @Sha2_512_256 sha512_256Monte

runMonteTest
    :: forall a
    . Hash a
    => Coercible a BS.ShortByteString
    => MonteFile
    -> Spec
runMonteTest = monteAssert
    (\l a b -> it l (a == b))
    (BS.fromShort . coerce . hashByteString_ @a)

