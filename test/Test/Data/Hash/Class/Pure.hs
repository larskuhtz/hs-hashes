{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UnboxedTuples #-}

-- |
-- Module: Test.Data.Hash.Class.Pure
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Test.Data.Hash.Class.Pure
( tests
, run
) where

import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Short as BS
import qualified Data.ByteString.Unsafe as B

import Foreign.Marshal
import Foreign.Ptr

import GHC.Exts
import GHC.IO
import GHC.Word

import Test.QuickCheck
import Test.Syd

-- internal modules

import Data.Hash.Class.Pure.Salted

-- -------------------------------------------------------------------------- --
--

tests :: Spec
tests = do
    prop "prop_hashByteString" prop_hashByteString
    prop "prop_hashByteStringLazy" prop_hashByteStringLazy
    prop "prop_hashShortByteString" prop_hashShortByteString
    prop "prop_hashStorable" prop_hashStorable
    prop "prop_hashPtr" prop_hashPtr
    prop "prop_hashByteArray" prop_hashByteArray

run :: IO ()
run = do
    putStrLn "prop_hashByteString"
    quickCheck prop_hashByteString
    putStrLn "prop_hashByteStringLazy"
    quickCheck prop_hashByteStringLazy
    putStrLn "prop_hashShortByteString"
    quickCheck prop_hashShortByteString
    putStrLn "prop_hashStorable"
    quickCheck prop_hashStorable
    putStrLn "prop_hashPtr"
    quickCheck prop_hashPtr
    putStrLn "prop_hashByteArray"
    quickCheck prop_hashByteArray

word8sToWord64 :: [Word8] -> Word64
word8sToWord64 = foldr (\b c -> fromIntegral b + shiftL c 8) 0

newtype TestHash = TestHash { _getTestHash :: [Word8] }
    deriving (Eq, Ord, Show)

instance IncrementalHash TestHash where
    type Context TestHash = [Word8]
    update ctx p l = (ctx ++) <$> peekArray l p
    finalize = TestHash

instance Hash TestHash where
    type Salt TestHash = ()
    initialize _ = []

prop_hashStorable :: Word64 -> Property
prop_hashStorable b = word8sToWord64 (_getTestHash $ hashStorable @TestHash () b) === b

prop_hashPtr :: [Word8] -> Property
prop_hashPtr b = unsafeDupablePerformIO $
    B.unsafeUseAsCStringLen (B.pack b) $ \(ptr, len) -> do
        return $ unsafeDupablePerformIO (hashPtr @TestHash () (castPtr ptr) len) === TestHash b

prop_hashByteString :: [Word8] -> Property
prop_hashByteString b = hashByteString @TestHash () (B.pack b) === TestHash b

prop_hashByteStringLazy :: [Word8] -> Property
prop_hashByteStringLazy b = hashByteStringLazy @TestHash () (BL.pack b) === TestHash b

prop_hashShortByteString :: [Word8] -> Property
prop_hashShortByteString b = hashShortByteString @TestHash () (BS.pack b) === TestHash b

prop_hashByteArray :: [Word8] -> Property
prop_hashByteArray bytes = unsafeDupablePerformIO $ IO $ \s0 ->
    case newPinnedByteArray# size s0 of
        (# s1, a# #) ->
            case copyToArray 0# bytes a# s1 of
                s2 -> case unsafeFreezeByteArray# a# s2 of
                    (# s3, b# #) ->
                        let r = hashByteArray @TestHash () b# === TestHash bytes
                        in (# s3, r #)
  where
    !(I# size) = length bytes

    copyToArray _ [] _ s = s
    copyToArray i ((W8# h):t) a s = case writeWord8Array# a i h s of
        s' -> copyToArray (i +# 1#) t a s'
