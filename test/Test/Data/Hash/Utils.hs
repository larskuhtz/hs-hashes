{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE UnboxedTuples #-}

-- |
-- Module: Test.Data.Hash.Utils
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Test.Data.Hash.Utils
( tests
) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B

import Foreign.Marshal
import Foreign.Ptr
import Foreign.Storable

import GHC.Exts
import GHC.IO
import GHC.Word

import Test.QuickCheck

-- internal modules

import Data.Hash.Utils

-- -------------------------------------------------------------------------- --
--

tests :: IO ()
tests = do
    putStrLn "prop_hashByteString"
    quickCheck prop_hashByteString
    putStrLn "prop_hashStorable"
    quickCheck prop_hashStorable
    putStrLn "prop_hashPtr"
    quickCheck prop_hashPtr
    putStrLn "prop_hashByteArray"
    quickCheck prop_hashByteArray

ptrToList :: Ptr Word8 -> Int -> IO [Word8]
ptrToList = flip peekArray

prop_hashStorable :: Word64 -> Property
prop_hashStorable b = hashStorable (\ptr _ -> peek (castPtr ptr)) b === b

prop_hashPtr :: [Word8] -> Property
prop_hashPtr b = unsafeDupablePerformIO $
    B.unsafeUseAsCStringLen (B.pack b) $ \(ptr, len) -> do
        return $ hashPtr ptrToList (castPtr ptr) len === b

prop_hashByteString :: [Word8] -> Property
prop_hashByteString b = hashByteString ptrToList (B.pack b) === b

prop_hashByteArray :: [Word8] -> Property
prop_hashByteArray bytes = unsafeDupablePerformIO $ IO $ \s0 ->
    case newPinnedByteArray# size s0 of
        (# s1, a# #) ->
            case copyToArray 0# bytes a# s1 of
                s2 -> case unsafeFreezeByteArray# a# s2 of
                    (# s3, b# #) ->
                        let r = hashByteArray ptrToList b# === bytes
                        in (# s3, r #)
  where
    !(I# size) = length bytes

    copyToArray _ [] _ s = s
    copyToArray i ((W8# h):t) a s = case writeWord8Array# a i h s of
        s' -> copyToArray (i +# 1#) t a s'
