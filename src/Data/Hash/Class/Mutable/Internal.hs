{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE ImportQualifiedPost #-}

-- |
-- Module: Data.Hash.Class.Mutable.Internal
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Incremental and Resetable Mutable Hashes
--
module Data.Hash.Class.Mutable.Internal
(
-- * Incremental Hashes
  IncrementalHash(..)
, updateByteString
, updateByteStringLazy
, updateShortByteString
, updateStorable
, updateByteArray

-- * Resetable Hashes
, ResetableHash(..)
) where

import Data.Array.Byte
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Data.ByteString.Short qualified as BS
import Data.ByteString.Unsafe qualified as B
import Data.Kind
import Data.Word

import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils
import Foreign.Ptr
import Foreign.Storable

import GHC.Exts
import GHC.IO

-- -------------------------------------------------------------------------- --
-- Incremental Mutable Hashes

class IncrementalHash a where
    type Context a :: Type

    -- | It is responsibility of the caller to ensure that the pointer stays
    -- alive and valid until the function returns.
    --
    -- The default implementation is in terms of 'update#' and copies the
    -- contents of the ptr to a (unpinned) 'ByteArray#'.
    --
    updatePtr :: Context a -> Ptr Word8 -> Int -> IO ()
    updatePtr ctx ptr i = do
        (BS.SBS arr) <- BS.packCStringLen (castPtr ptr, i)
        update# @a ctx arr
    {-# INLINE updatePtr #-}

    -- The implementation must not assume that the array is pinned. If needed
    -- one may use 'isByteArrayPinned#' to determined whether the array is
    -- pinned.
    --
    -- Note, that since GHC version 8.4 it is sound to make /unsafe/ foreign
    -- functions calls directly on ByteArray#. GHC will also keep the array
    -- alive until the end of the unsafe call.
    --
    -- Where possible, it is also recommended to /unsafe/ calls in the
    -- implementation, splitting up possibly long running calls to foreign hash
    -- implementations on large data into short calls on smaller chunks.
    --
    -- The default implementation is in terms of 'update' and has to copy the
    -- content of array in case it is unpinned. It also ensure that pinned
    -- arrays are kept alive as long as needed.
    --
    update# :: Context a -> ByteArray# -> IO ()
    update# ctx arr = case isByteArrayPinned# arr of
        -- Pinned ByteArray. We have to keep it alive. We don't know how update
        -- is implemented. So just 'touch#' is not an option.
        1# -> IO $ \s -> keepAlive# arr s $ \s' ->
            case unIO (updatePtr @a ctx (Ptr (byteArrayContents# arr)) (I# size)) s' of
                (# s'', () #) -> (# s'', () #)

        -- Unpinned ByteArray, copy content to newly allocated pinned ByteArray
        _ -> allocaBytes (I# size) $ \ptr@(Ptr addr) -> IO $ \s0 ->
            case copyByteArrayToAddr# arr 0# addr size s0 of
                s1 -> case updatePtr @a ctx ptr (I# size) of
                    IO run -> run s1
      where
        size = sizeofByteArray# arr
    {-# INLINE update# #-}

    finalize :: Context a -> IO a

    {-# MINIMAL (updatePtr | update#), finalize #-}

updateByteString
    :: forall a
    . IncrementalHash a
    => Context a
    -> B.ByteString
    -> IO ()
updateByteString ctx b = B.unsafeUseAsCStringLen b $ \(!p, !l) ->
    updatePtr @a ctx (castPtr p) l
{-# INLINE updateByteString #-}

updateByteStringLazy
    :: forall a
    . IncrementalHash a
    => Context a
    -> BL.ByteString
    -> IO ()
updateByteStringLazy ctx = mapM_ (updateByteString @a ctx) . BL.toChunks
{-# INLINE updateByteStringLazy #-}

updateShortByteString
    :: forall a
    . IncrementalHash a
    => Context a
    -> BS.ShortByteString
    -> IO ()
updateShortByteString ctx (BS.SBS b) = update# @a ctx b
{-# INLINE updateShortByteString #-}

updateStorable
    :: forall a b
    . IncrementalHash a
    => Storable b
    => Context a
    -> b
    -> IO ()
updateStorable ctx b = with b $ \p -> updatePtr @a ctx (castPtr p) (sizeOf b)
{-# INLINE updateStorable #-}

updateByteArray
    :: forall a
    . IncrementalHash a
    => Context a
    -> ByteArray
    -> IO ()
updateByteArray ctx (ByteArray arr) = update# @a ctx arr
{-# INLINE updateByteArray #-}

-- -------------------------------------------------------------------------- --
-- Class of Resetable Hashes

class IncrementalHash a => ResetableHash a where
    reset :: Context a -> IO ()

