{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.Hash.Class.Mutable
-- Copyright: Copyright © 2021-2024 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Class of Salted Pure Hashes
--
module Data.Hash.Class.Mutable
( Hash(..)
, IncrementalHash(..)

-- * Hash functions
, hashPtr
, hashStorable
, hashByteString
, hashByteStringLazy
, hashShortByteString
, hashByteArray

-- ** Pure variants of hash functions
--
-- The following pure variants of the hash functions are implemented with
-- 'unsafePerformIO'. This is generally less efficient than running them
-- directly in 'IO'. Often the performance difference does not matter. However,
-- when many hashes are computed one should prefer the variants that run in
-- 'IO'. When a 'ResetableHash' instance is available it provides the most
-- efficient way to compute many hashes in a tight loop.

, hashPtr_
, hashStorable_
, hashByteString_
, hashByteStringLazy_
, hashShortByteString_
, hashByteArray_

-- * Incremental Hashing
, updateByteString
, updateByteStringLazy
, updateShortByteString
, updateStorable
, updateByteArray

-- * Resetable Hashes
, ResetableHash(..)
) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Short as BS
import Data.Word

import Foreign.Ptr
import Foreign.Storable

import GHC.Exts

import System.IO.Unsafe

-- internal modules

import Data.Hash.Class.Mutable.Internal

-- -------------------------------------------------------------------------- --
-- Class of Mutable Hashes

class IncrementalHash a => Hash a where
    initialize :: IO (Context a)

-- -------------------------------------------------------------------------- --
-- Hash Functions

hashPtr :: forall a . Hash a => Ptr Word8 -> Int -> IO a
hashPtr p n = do
    ctx <- initialize @a
    update @a ctx p n
    finalize ctx
{-# INLINE hashPtr #-}

hashByteString :: forall a . Hash a => B.ByteString -> IO a
hashByteString b = do
    ctx <- initialize @a
    updateByteString @a ctx b
    finalize ctx
{-# INLINE hashByteString #-}

hashByteStringLazy :: forall a . Hash a => BL.ByteString -> IO a
hashByteStringLazy b = do
    ctx <- initialize @a
    updateByteStringLazy @a ctx b
    finalize ctx
{-# INLINE hashByteStringLazy #-}

hashShortByteString :: forall a . Hash a => BS.ShortByteString -> IO a
hashShortByteString b = do
    ctx <- initialize @a
    updateShortByteString @a ctx b
    finalize ctx
{-# INLINE hashShortByteString #-}

hashStorable :: forall a b . Hash a => Storable b => b -> IO a
hashStorable b = do
    ctx <- initialize @a
    updateStorable @a ctx b
    finalize ctx
{-# INLINE hashStorable #-}

hashByteArray :: forall a . Hash a => ByteArray# -> IO a
hashByteArray b = do
    ctx <- initialize @a
    updateByteArray @a ctx b
    finalize ctx
{-# INLINE hashByteArray #-}

-- --------------------------------------------------------------------------
-- Pure variants of hashes

hashPtr_ :: forall a . Hash a => Ptr Word8 -> Int -> a
hashPtr_ a = unsafePerformIO . hashPtr a
{-# INLINE hashPtr_ #-}

hashByteString_ :: forall a . Hash a => B.ByteString -> a
hashByteString_ = unsafePerformIO . hashByteString
{-# INLINE hashByteString_ #-}

hashByteStringLazy_ :: forall a . Hash a => BL.ByteString -> a
hashByteStringLazy_ = unsafePerformIO . hashByteStringLazy
{-# INLINE hashByteStringLazy_ #-}

hashShortByteString_ :: forall a . Hash a => BS.ShortByteString -> a
hashShortByteString_ = unsafePerformIO . hashShortByteString
{-# INLINE hashShortByteString_ #-}

hashStorable_ :: forall a b . Hash a => Storable b => b -> a
hashStorable_ = unsafePerformIO . hashStorable
{-# INLINE hashStorable_ #-}

hashByteArray_ :: forall a . Hash a => ByteArray# -> a
hashByteArray_ a = unsafePerformIO $ hashByteArray a
{-# INLINE hashByteArray_ #-}

