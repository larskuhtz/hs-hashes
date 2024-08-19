{-# LANGUAGE CPP #-}
-- |
-- Module: Main
-- Copyright: Copyright © 2021-2024 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Main
( main
, tests
) where

import qualified Test.Data.Hash.FNV1
import qualified Test.Data.Hash.SipHash
import qualified Test.Data.Hash.Class.Pure

#if defined(WITH_OPENSSL)
import qualified Test.Data.Hash.SHA2
import qualified Test.Data.Hash.SHA3
import qualified Test.Data.Hash.Keccak
#endif

#if defined(TEST_CRYPTONITE)
import qualified Cryptonite
#endif

import Test.Hspec

main :: IO ()
main = hspec tests

tests :: Spec
tests = parallel $ do
    describe "Test.Data.Hash.FNV1.tests" Test.Data.Hash.FNV1.tests
    describe "Test.Data.Hash.SipHash.tests" Test.Data.Hash.SipHash.tests
    describe "Test.Data.Hash.Class.Pure" Test.Data.Hash.Class.Pure.tests

#if defined(WITH_OPENSSL)
    describe "Test.Data.Hash.SHA2" Test.Data.Hash.SHA2.tests
    describe "Test.Data.Hash.SHA3" Test.Data.Hash.SHA3.tests
    describe "Test.Data.Hash.Keccak" Test.Data.Hash.Keccak.tests
#endif

#if defined(TEST_CRYPTONITE)
    describe "Cryptonite" Cryptonite.tests
#endif

