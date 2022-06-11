{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.Hash.Class.Mutable
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Class of Salted Pure Hashes
--
module Data.Hash.Class.Mutable
( Hash(..)
, IncrementalHash(..)

, hashPtr
, hashStorable
, hashByteString
, hashByteStringLazy
, hashShortByteString
, hashByteArray

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
import Data.Word

import Foreign.Ptr
import Foreign.Storable

import GHC.Exts
import GHC.IO

-- internal modules

import Data.Hash.Class.Mutable.Internal

-- -------------------------------------------------------------------------- --
-- Class of Salted Pure Hashes

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

hashByteString :: forall a . Hash a => B.ByteString -> a
hashByteString b = unsafeDupablePerformIO $ do
    ctx <- initialize @a
    updateByteString @a ctx b
    finalize ctx
{-# INLINE hashByteString #-}

hashByteStringLazy :: forall a . Hash a => BL.ByteString -> a
hashByteStringLazy b = unsafeDupablePerformIO $ do
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

