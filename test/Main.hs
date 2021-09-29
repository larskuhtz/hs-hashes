
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
import qualified Test.Data.Hash.Utils

main :: IO ()
main = do
    putStrLn "Test.Data.Hash.FNV1.tests: " >> Test.Data.Hash.FNV1.tests
    putStrLn "Test.Data.Hash.SipHash.tests: " >> Test.Data.Hash.SipHash.tests
    putStrLn "Test.Data.Hash.Utils:" >> Test.Data.Hash.Utils.tests

