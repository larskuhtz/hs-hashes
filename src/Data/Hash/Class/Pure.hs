{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.Hash.Class.Pure
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Hashes with pure context
--
module Data.Hash.Class.Pure
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

-- * Utilities
, initializeWithSalt
) where

import Control.Monad

import Data.Array.Byte
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Data.ByteString.Short qualified as BS
import Data.Word

import Foreign.Ptr
import Foreign.Storable

import GHC.Exts

import System.IO.Unsafe

-- internal modules

import Data.Hash.Class.Pure.Internal

-- -------------------------------------------------------------------------- --
-- Class of Pure Hashes

class IncrementalHash a => Hash a where
    initialize :: Context a

-- -------------------------------------------------------------------------- --
-- hash Functions

hashPtr :: forall a. Hash a => Ptr Word8 -> Int -> IO a
hashPtr p n = finalize <$!> updatePtr @a (initialize @a) p n
{-# INLINE hashPtr #-}

hashByteString :: forall a . Hash a => B.ByteString -> a
hashByteString b = finalize $! updateByteString @a (initialize @a) b
{-# INLINE hashByteString #-}

hashByteStringLazy :: forall a . Hash a => BL.ByteString -> a
hashByteStringLazy b = finalize $! updateByteStringLazy @a (initialize @a) b
{-# INLINE hashByteStringLazy #-}

hashShortByteString :: forall a . Hash a => BS.ShortByteString -> a
hashShortByteString b = finalize $! updateShortByteString @a (initialize @a) b
{-# INLINE hashShortByteString #-}

hashStorable :: forall a b . Hash a => Storable b => b -> a
hashStorable b = finalize $! updateStorable @a (initialize @a) b
{-# INLINE hashStorable #-}

hashByteArray :: forall a . Hash a => ByteArray -> a
hashByteArray b = finalize $! updateByteArray @a (initialize @a) b
{-# INLINE hashByteArray #-}

hashByteArray# :: forall a . Hash a => ByteArray# -> a
hashByteArray# b = finalize $! unsafeDupablePerformIO $
    update# @a (initialize @a) b 0# (sizeofByteArray# b)

{-# INLINE hashByteArray# #-}

-- -------------------------------------------------------------------------- --
-- Utilities

-- | Utility function to initialize a hash with a salt
--
initializeWithSalt :: forall a s . Hash a => Storable s => s -> Context a
initializeWithSalt = updateStorable @a $ initialize @a
{-# INLINE initializeWithSalt #-}

