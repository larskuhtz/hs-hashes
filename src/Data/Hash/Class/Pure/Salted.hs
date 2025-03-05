{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Data.Hash.Class.Pure.Salted
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Data.Hash.Class.Pure.Salted
( Hash(..)
, IncrementalHash(..)
, digestSize

, hashPtr
, hashStorable
, hashByteString
, hashByteStringLazy
, hashShortByteString
, hashByteArray
, hashByteArray#

-- * Incremental Hashing
, updateByteString
, updateByteStringLazy
, updateShortByteString
, updateStorable
, updateByteArray
) where

import Control.Monad

import Data.Array.Byte
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Data.ByteString.Short qualified as BS
import Data.Kind
import Data.Word

import Foreign.Ptr
import Foreign.Storable

import GHC.Exts

import System.IO.Unsafe

-- internal modules

import Data.Hash.Class.Pure.Internal

-- -------------------------------------------------------------------------- --
-- Class of Pure Salted Hashes

class IncrementalHash a => Hash a where
    type Salt a :: Type
    initialize :: Salt a -> Context a

-- -------------------------------------------------------------------------- --
-- hash Functions

hashPtr :: forall a. Hash a => Salt a -> Ptr Word8 -> Int -> IO a
hashPtr k p n = finalize <$!> updatePtr @a (initialize @a k) p n
{-# INLINE hashPtr #-}

hashByteString :: forall a . Hash a => Salt a -> B.ByteString -> a
hashByteString k b = finalize $! updateByteString @a (initialize @a k) b
{-# INLINE hashByteString #-}

hashByteStringLazy :: forall a . Hash a => Salt a -> BL.ByteString -> a
hashByteStringLazy k b = finalize $! updateByteStringLazy @a (initialize @a k) b
{-# INLINE hashByteStringLazy #-}

hashShortByteString :: forall a . Hash a => Salt a -> BS.ShortByteString -> a
hashShortByteString k b = finalize $! updateShortByteString @a (initialize @a k) b
{-# INLINE hashShortByteString #-}

hashStorable :: forall a b . Hash a => Storable b => Salt a -> b -> a
hashStorable k b = finalize $! updateStorable @a (initialize @a k) b
{-# INLINE hashStorable #-}

hashByteArray :: forall a . Hash a => Salt a -> ByteArray -> a
hashByteArray k b = finalize $! updateByteArray @a (initialize @a k) b
{-# INLINE hashByteArray #-}

hashByteArray# :: forall a . Hash a => Salt a -> ByteArray# -> a
hashByteArray# k b = finalize $! unsafeDupablePerformIO $
    update# @a (initialize @a k) b 0# (sizeofByteArray# b)
{-# INLINE hashByteArray# #-}

