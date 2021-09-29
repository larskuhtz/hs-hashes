{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE UnboxedTuples #-}

-- |
-- Module: Data.Hash.Utils
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Data.Hash.Utils
(
-- * Pure API
  hashStorable
, hashStorable_
, hashByteString
, hashByteString_
, hashByteArray
, hashByteArray_
, hashPtr
, hashPtr_

-- * IO API
, hashStorableIO
, hashStorableIO_
, hashByteStringIO
, hashByteStringIO_
, hashByteArrayIO
, hashByteArrayIO_
) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import Data.Word

import Foreign.Marshal.Utils
import Foreign.Ptr
import Foreign.Storable

import GHC.Exts
import GHC.IO
import Foreign.Marshal.Alloc

-- -------------------------------------------------------------------------- --
-- Pure API

-- Storable

hashStorable :: Storable a => (Ptr Word8 -> Int -> IO b) -> a -> b
hashStorable f = unsafeDupablePerformIO . hashStorableIO f
{-# INLINE hashStorable #-}

hashStorable_ :: Storable a => (Ptr Word8 -> Int -> b -> IO b) -> a -> b -> b
hashStorable_ f a = unsafeDupablePerformIO . hashStorableIO_ f a
{-# INLINE hashStorable_ #-}

-- ByteString

hashByteString :: (Ptr Word8 -> Int -> IO b) -> B.ByteString -> b
hashByteString f = unsafeDupablePerformIO . hashByteStringIO f
{-# INLINE hashByteString #-}

hashByteString_ :: (Ptr Word8 -> Int -> b -> IO b) -> B.ByteString -> b -> b
hashByteString_ f a = unsafeDupablePerformIO . hashByteStringIO_ f a
{-# INLINE hashByteString_ #-}

-- ByteArray

hashByteArray :: (Ptr Word8 -> Int -> IO b) -> ByteArray# -> b
hashByteArray f a# = unsafeDupablePerformIO $! hashByteArrayIO f a#
{-# INLINE hashByteArray #-}

hashByteArray_ :: (Ptr Word8 -> Int -> b -> IO b) -> ByteArray# -> b -> b
hashByteArray_ f a# = unsafeDupablePerformIO . hashByteArrayIO_ f a#
{-# INLINE hashByteArray_ #-}

-- Ptr

hashPtr :: (Ptr Word8 -> Int -> IO b) -> Ptr Word8 -> Int -> b
hashPtr f ptr = unsafeDupablePerformIO . f ptr
{-# INLINE hashPtr #-}

hashPtr_ :: (Ptr Word8 -> Int -> b -> IO b) -> Ptr Word8 -> Int -> b -> b
hashPtr_ f ptr l = unsafeDupablePerformIO . f ptr l
{-# INLINE hashPtr_ #-}

-- -------------------------------------------------------------------------- --
-- IO API

-- Storable

hashStorableIO :: Storable a => (Ptr Word8 -> Int -> IO b) -> a -> IO b
hashStorableIO f a = with a $ \ptr -> f (castPtr ptr) (sizeOf a)
{-# INLINE hashStorableIO #-}

hashStorableIO_ :: Storable a => (Ptr Word8 -> Int -> b -> IO b) -> a -> b -> IO b
hashStorableIO_ f a b = with a $ \ptr -> f (castPtr ptr) (sizeOf a) b
{-# INLINE hashStorableIO_ #-}

-- ByteString

hashByteStringIO :: (Ptr Word8 -> Int -> IO b) -> B.ByteString -> IO b
hashByteStringIO f a = B.unsafeUseAsCStringLen a $ \(!p, !l) -> f (castPtr p) l
{-# INLINE hashByteStringIO #-}

hashByteStringIO_ :: (Ptr Word8 -> Int -> b -> IO b) -> B.ByteString -> b -> IO b
hashByteStringIO_ f a b = B.unsafeUseAsCStringLen a $ \(!p, !l) -> f (castPtr p) l b
{-# INLINE hashByteStringIO_ #-}

-- ByteArray

hashByteArrayIO :: (Ptr Word8 -> Int -> IO b) -> ByteArray# -> IO b
hashByteArrayIO f a# = case isByteArrayPinned# a# of
    -- Pinned ByteArray
    1# -> f (Ptr (byteArrayContents# a#)) (I# size#)

    -- Unpinned ByteArray, copy content to newly allocated pinned ByteArray
    _ -> allocaBytes (I# size#) $ \ptr@(Ptr addr#) -> IO $ \s0 ->
        case copyByteArrayToAddr# a# 0# addr# size# s0 of
            s1 -> case f ptr (I# size#) of
                IO run -> run s1
  where
    size# = sizeofByteArray# a#
{-# INLINE hashByteArrayIO #-}


hashByteArrayIO_ :: (Ptr Word8 -> Int -> b -> IO b) -> ByteArray# -> b -> IO b
hashByteArrayIO_ f a# b = case isByteArrayPinned# a# of
    -- Pinned ByteArray
    1# -> f (Ptr (byteArrayContents# a#)) (I# size#) b

    -- Unpinned ByteArray, copy content to newly allocated pinned ByteArray
    _ -> allocaBytes (I# size#) $ \ptr@(Ptr addr#) -> IO $ \s0 ->
        case copyByteArrayToAddr# a# 0# addr# size# s0 of
            s1 -> case f ptr (I# size#) b of
                IO run -> run s1
  where
    size# = sizeofByteArray# a#
{-# INLINE hashByteArrayIO_ #-}

