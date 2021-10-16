{-# LANGUAGE AllowAmbiguousTypes #-}
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

-- * Utilities
, initializeWithSalt
) where

import Control.Monad

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Short as BS
import Data.Word

import Foreign.Ptr
import Foreign.Storable

import GHC.Exts

-- internal modules

import Data.Hash.Class.Pure.Internal

-- -------------------------------------------------------------------------- --
-- Class of Pure Hashes

class IncrementalHash a => Hash a where
    initialize :: Context a

-- -------------------------------------------------------------------------- --
-- hash Functions

hashPtr :: forall a. Hash a => Ptr Word8 -> Int -> IO a
hashPtr p n = finalize <$!> update @a (initialize @a) p n
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

hashByteArray :: forall a . Hash a => ByteArray# -> a
hashByteArray b = finalize $! updateByteArray @a (initialize @a) b
{-# INLINE hashByteArray #-}

-- -------------------------------------------------------------------------- --
-- Utilities

-- | Utility function to initialize a hash with a salt
--
initializeWithSalt :: forall a s . Hash a => Storable s => s -> Context a
initializeWithSalt = updateStorable @a $ initialize @a
{-# INLINE initializeWithSalt #-}

