{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Data.Hash.Class.Pure.Internal
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Incremental Pure Hashes
--
module Data.Hash.Class.Pure.Internal
( IncrementalHash(..)
, updateByteString
, updateByteStringLazy
, updateShortByteString
, updateStorable
, updateByteArray
) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Short as BS
import qualified Data.ByteString.Unsafe as B
import Data.Kind
import Data.Word

import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils
import Foreign.Ptr
import Foreign.Storable

import GHC.Exts
import GHC.IO

-- -------------------------------------------------------------------------- --
-- Incremental Pure Hashes

class IncrementalHash a where
    type Context a :: Type
    update :: Context a -> Ptr Word8 -> Int -> IO (Context a)
    finalize :: Context a -> a

updateByteString :: forall a . IncrementalHash a => Context a -> B.ByteString -> Context a
updateByteString !ctx !b = unsafeDupablePerformIO $!
    B.unsafeUseAsCStringLen b $ \(!p, !l) -> update @a ctx (castPtr p) l
{-# INLINE updateByteString #-}

updateByteStringLazy
    :: forall a
    . IncrementalHash a
    => Context a
    -> BL.ByteString
    -> Context a
updateByteStringLazy = BL.foldlChunks (updateByteString @a)
{-# INLINE updateByteStringLazy #-}

updateShortByteString
    :: forall a
    . IncrementalHash a
    => Context a
    -> BS.ShortByteString
    -> Context a
updateShortByteString !ctx b = unsafeDupablePerformIO $!
    BS.useAsCStringLen b $ \(!p, !l) -> update @a ctx (castPtr p) l
{-# INLINE updateShortByteString #-}

updateStorable
    :: forall a b
    . IncrementalHash a
    => Storable b
    => Context a
    -> b
    -> Context a
updateStorable !ctx b = unsafeDupablePerformIO $!
    with b $ \p -> update @a ctx (castPtr p) (sizeOf b)
{-# INLINE updateStorable #-}

updateByteArray
    :: forall a
    . IncrementalHash a
    => Context a
    -> ByteArray#
    -> Context a
updateByteArray ctx a# = unsafeDupablePerformIO $!
    case isByteArrayPinned# a# of
        -- Pinned ByteArray
        1# -> update @a ctx (Ptr (byteArrayContents# a#)) (I# size#)

        -- Unpinned ByteArray, copy content to newly allocated pinned ByteArray
        _ -> allocaBytes (I# size#) $ \ptr@(Ptr addr#) -> IO $ \s0 ->
            case copyByteArrayToAddr# a# 0# addr# size# s0 of
                s1 -> case update @a ctx ptr (I# size#) of
                    IO run -> run s1
  where
    size# = sizeofByteArray# a#
{-# INLINE updateByteArray #-}

