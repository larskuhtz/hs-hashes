{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Data.Hash.Class.Mutable.Salted
-- Copyright: Copyright © 2021-2024 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Class of Salted Mutable Hashes
--
module Data.Hash.Class.Mutable.Salted
( Hash(..)

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
) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Short as BS
import Data.Kind
import Data.Word

import Foreign.Ptr
import Foreign.Storable

import GHC.Exts
import GHC.IO

-- internal modules

import Data.Hash.Class.Mutable.Internal

-- -------------------------------------------------------------------------- --
-- Class of Salted Mutable Hashes

class IncrementalHash a => Hash a where
    type Salt a :: Type
    initialize :: Salt a -> IO (Context a)

-- -------------------------------------------------------------------------- --
-- Hash Functions

hashPtr :: forall a . Hash a => Salt a -> Ptr Word8 -> Int -> IO a
hashPtr k p n = do
    ctx <- initialize @a k
    update @a ctx p n
    finalize ctx
{-# INLINE hashPtr #-}

hashByteString :: forall a . Hash a => Salt a -> B.ByteString -> IO a
hashByteString k b = do
        ctx <- initialize @a k
        updateByteString @a ctx b
        finalize ctx
{-# INLINE hashByteString #-}

hashByteStringLazy :: forall a . Hash a => Salt a -> BL.ByteString -> IO a
hashByteStringLazy k b = do
        ctx <- initialize @a k
        updateByteStringLazy @a ctx b
        finalize ctx
{-# INLINE hashByteStringLazy #-}

hashShortByteString :: forall a . Hash a => Salt a -> BS.ShortByteString -> IO a
hashShortByteString k b = do
        ctx <- initialize @a k
        updateShortByteString @a ctx b
        finalize ctx
{-# INLINE hashShortByteString #-}

hashStorable :: forall a b . Hash a => Storable b => Salt a -> b -> IO a
hashStorable k b = do
        ctx <- initialize @a k
        updateStorable @a ctx b
        finalize ctx
{-# INLINE hashStorable #-}

hashByteArray :: forall a . Hash a => Salt a -> ByteArray# -> IO a
hashByteArray k b = do
        ctx <- initialize @a k
        updateByteArray @a ctx b
        finalize ctx
{-# INLINE hashByteArray #-}

-- -------------------------------------------------------------------------- --
-- Pure variants

hashPtr_ :: forall a . Hash a => Salt a -> Ptr Word8 -> Int -> a
hashPtr_ s ptr = unsafePerformIO . hashPtr s ptr
{-# INLINE hashPtr_ #-}

hashByteString_ :: forall a . Hash a => Salt a -> B.ByteString -> a
hashByteString_ s = unsafePerformIO . hashByteString s
{-# INLINE hashByteString_ #-}

hashByteStringLazy_ :: forall a . Hash a => Salt a -> BL.ByteString -> a
hashByteStringLazy_ s = unsafePerformIO . hashByteStringLazy s
{-# INLINE hashByteStringLazy_ #-}

hashShortByteString_ :: forall a . Hash a => Salt a -> BS.ShortByteString -> a
hashShortByteString_ s = unsafePerformIO . hashShortByteString s
{-# INLINE hashShortByteString_ #-}

hashStorable_ :: forall a b . Hash a => Storable b => Salt a -> b -> a
hashStorable_ s = unsafePerformIO . hashStorable s
{-# INLINE hashStorable_ #-}

hashByteArray_ :: forall a . Hash a => Salt a -> ByteArray# -> a
hashByteArray_ s a = unsafePerformIO $ hashByteArray s a
{-# INLINE hashByteArray_ #-}

