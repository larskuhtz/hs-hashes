{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MagicHash #-}
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

import Control.Monad

import Data.ByteString qualified as B
import Data.ByteString.Short qualified as BS
import Data.Coerce

import GHC.Exts (Int#)
import GHC.Int (Int(I#))

import Test.Hspec
import Test.Hash.SHA

-- internal modules

import Data.Hash.SHA2

-- -------------------------------------------------------------------------- --
--

tests :: Spec
tests = do
    describe "SHA2 misc tests" $ do
        describe "offset tests" $ do
            testOffsets
            testOffsets2
    describe "SHA2 Test Vectors" $ do
        shortMsgTests
        longMsgTests
        monteTests

-- -------------------------------------------------------------------------- --
-- Miscelaneous Tests

toI# :: Int -> Int#
toI# !(I# i#) = i#

testOffsets :: Spec
testOffsets = do
    it ("produces the same result on different offsets of a constant input") $ do
        shouldReturn runAll True
    it ("succeeds on empty input arrays") $ do
        nullHash <- hashShortByteString @Sha2_256 ""
        runEmpty <- run 10 0
        shouldBe runEmpty nullHash
  where
    !(BS.SBS arr) = BS.replicate 1024 0x5f
    run i l = do
        ctx <- initialize @Sha2_256
        update# @Sha2_256 ctx arr (toI# i) (toI# l)
        finalize @Sha2_256 ctx
    runAll = do
        a <- run 0 35
        foldM (\c i -> ((&&) c) . (== a) <$> run i 35) True [1..100]

testOffsets2 :: Spec
testOffsets2 = do
    it ("produces the same result on different copies of the same data at different offsets") $
        shouldReturn (runAll 0) True
    it ("does not produce the same result on different copies of the same data at different offsets if offsets are wrong") $
        shouldReturn (runAll 1) False
    it ("fails if the input array is too small") $
        shouldThrow (runAll 65) (const True :: Selector OpenSslException)
  where
    !(BS.SBS arr) = BS.pack $ concat $ replicate 5 [0..63]
    run i x = do
        ctx <- initialize @Sha2_256
        update# @Sha2_256 ctx arr (toI# (i * 64 + x)) (toI# 64)
        finalize @Sha2_256 ctx
    runAll x = do
        a <- run 0 0
        foldM (\c i -> ((&&) c) . (== a) <$> run i x) True [0..3]

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
    (\l a b -> it l (a == b && B.length a == digestSize @a))
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
    (\l a b -> it l (a == b && B.length a == digestSize @a))
    (BS.fromShort . coerce . hashByteString_ @a)

