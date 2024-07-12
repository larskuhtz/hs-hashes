{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Test.Data.Hash.Keccak
-- Copyright: Copyright © 2022 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Test.Data.Hash.Keccak
( tests
) where

import Data.ByteString qualified as B
import Data.ByteString.Short qualified as BS
import Data.Coerce
import Data.String

import Test.QuickCheck
import Test.Syd

-- internal modules

import Data.Hash.Internal.Utils
import Data.Hash.Keccak
import Data.Hash.SHA2
import Data.Hash.SHA3

-- -------------------------------------------------------------------------- --

tests :: Spec
tests = describe "Keccak Test Vectors" $ do
    describe "Keccak256" $ do
        examples256
        badExamples256
        correctKeccakVersion

-- -------------------------------------------------------------------------- --
-- Trivial Tests

examples256 :: Spec
examples256 = describe "example hashes" $ do
    succeed @Keccak256 "" "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    succeed @Keccak256 "1234" "56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432"
    succeed @Keccak256 helloWorld "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"

badExamples256 :: Spec
badExamples256 = describe "bad example hashes fail" $ do
    failTest @Keccak256 "" "c5d2460186f7233c927e7db2dcc603c0e500b653ca82273b7bfad8045d85a470"
    failTest @Keccak256 "00" "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    failTest @Keccak256 "1234" "56570de287d73cd1cb6092bb8fdef6173974955fdef345ae579ee9f475ea7432"
    failTest @Keccak256 "0234" "56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432"
    failTest @Keccak256 "1235" "56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432"
    failTest @Keccak256 helloWorld "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fae"
    failTest @Keccak256 helloWorld "57173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
    failTest @Keccak256 helloWorld "07173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"

correctKeccakVersion :: Spec
correctKeccakVersion = describe "correct Keccak version" $ do
    it "is 32 bytes long" $
        shouldBe (BS.length (coerce (hashByteString_ @Keccak256 ""))) 32
    describe "Keccak256 is not SHA3" $ do
        failTest @Sha3_256 "" "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        failTest @Sha3_256 "1234" "56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432"
        failTest @Sha3_256 helloWorld "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"

        it "yields different results" $ property $ \l ->
            let bs = fromString @B.ByteString l
            in (hashByteString_ @Keccak256 bs) =/= coerce (hashByteString_ @Sha3_256 bs)

    describe "Keccak256 is not SHA2" $ do
        failTest @Sha2_256 "" "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        failTest @Sha2_256 "1234" "56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432"
        failTest @Sha2_256 helloWorld "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"

        it "yields different results" $ property $ \l ->
            let bs = fromString @B.ByteString l
            in (hashByteString_ @Keccak256 bs) =/= coerce (hashByteString_ @Sha2_256 bs)

-- -------------------------------------------------------------------------- --
-- Tools

helloWorld :: B16ShortByteString
helloWorld = B16ShortByteString "hello world"

succeed
    :: forall a
    . Hash a
    => Eq a
    => Show a
    => Coercible a B16ShortByteString
    => B16ShortByteString
    -> a
    -> TestDefM '[] () ()
succeed a b = do
    it (show a) $ shouldBe (hashShortByteString_ @a $ coerce a) b

failTest
    :: forall a
    . Hash a
    => Eq a
    => Show a
    => Coercible a B16ShortByteString
    => B16ShortByteString
    -> a
    -> TestDefM '[] () ()
failTest a b = do
    it (show a) $ shouldNotBe (hashShortByteString_ @a $ coerce a) b

