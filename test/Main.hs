{-# LANGUAGE CPP #-}
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

import qualified Test.Data.Hash.FNV1
import qualified Test.Data.Hash.SipHash
import qualified Test.Data.Hash.Class.Pure

#if defined(TEST_CRYPTONITE)
import Cryptonite
#endif

main :: IO ()
main = do
    putStrLn "Test.Data.Hash.FNV1.tests: " >> Test.Data.Hash.FNV1.tests
    putStrLn "Test.Data.Hash.SipHash.tests: " >> Test.Data.Hash.SipHash.tests
    putStrLn "Test.Data.Hash.Class.Pure:" >> Test.Data.Hash.Class.Pure.tests
#if defined(TEST_CRYPTONITE)
    run
#endif

