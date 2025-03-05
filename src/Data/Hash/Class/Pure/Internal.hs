{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}

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
, digestSize
, updateByteString
, updateByteStringLazy
, updateShortByteString
, updateStorable
, updateByteArray
) where

import Control.Exception
import Control.Monad

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
import GHC.TypeNats

---- -------------------------------------------------------------------------- --
-- Exceptions

newtype PureHashException = PureHashException String
    deriving (Show)

instance Exception PureHashException

 -------------------------------------------------------------------------- --
-- Incremental Pure Hashes

class KnownNat (DigestSize a) => IncrementalHash a where
    type Context a :: Type

    -- | Size of the Digest in Bytes
    --
    type DigestSize a :: Natural

    -- | Update the hash context with the contents of a Ptr.
    --
    -- It is responsibility of the caller to ensure that the pointer is valid
    -- during the operations. In particular, if the pointer points to memory on
    -- the Haskell heap, that memory must be pinned and must be kept alive.
    --
    -- The default implementation is in terms of 'update#' and copies the
    -- contents of the ptr to an unpinned 'ByteArray#'.
    --
    updatePtr
        :: Context a
            -- ^ the hash context
        -> Ptr Word8
            -- ^ Pointer to the input data
        -> Int
            -- ^ The size of the input data in bytes
        -> IO (Context a)
    updatePtr ctx ptr !i@(I# i#) = do
        (BS.SBS arr) <- BS.packCStringLen (castPtr ptr, i)
        update# @a ctx arr 0# i#
    {-# INLINE updatePtr #-}

    -- | Update the hash context with the contents of a (possibly unpinned)
    -- ByteArray# at the given offset.
    --
    -- It is the responsibility of the caller to guarantee that the range
    -- @[offset, offset+length-1]@ is indeed in the array. The implementation
    -- may check that but that is not a requirement.
    --
    -- The implementation must not assume that the array is pinned.
    --
    -- Since GHC version 8.4 it it is sound to make /unsafe/ foreign functions
    -- calls directly on ByteArray#. GHC will also keep the array alive until
    -- the end of the unsafe call.
    --
    -- When possible, it is also recommended to use /unsafe/ calls in the
    -- implementation. Possibly long running calls to foreign hash
    -- implementations on large data may be split into short calls on smaller
    -- chunks.
    --
    -- The default implementation is in terms of 'updatePtr' and has to copy the
    -- content of array in case it is unpinned. It also ensure that pinned
    -- arrays are kept alive as long as needed.
    --
    update#
        :: Context a
            -- ^ The hash context
        -> ByteArray#
            -- ^ The (possibly unpinned) byte array with the input data
        -> Int#
            -- ^ The offset into the input byte array
        -> Int#
            -- ^ The size of the input data in bytes
        -> IO (Context a)
    update# ctx arr# off# len# = do
        -- Assert that the addressed memory is within the input array
        when (isTrue# (size# <# off# +# len#)) $
            throwIO $ PureHashException "input array to small"

        if isTrue# (isByteArrayPinned# arr#)
          then
            -- Pinned ByteArray. We have to keep it alive. We don't know how
            -- updatePtr is implemented. So just 'touch#' is not an option.
            IO $ \s0 -> keepAlive# arr# s0 $ \s1 ->
                case unIO (updatePtr @a ctx (Ptr contAddr) (I# len#)) s1 of
                    (# s2, ctx' #) -> (# s2, ctx' #)
          else
            -- Unpinned ByteArray, copy content to temporarily allocated memory
            allocaBytes (I# len#) $ \ptr@(Ptr addr) -> IO $ \s0 ->
                case copyByteArrayToAddr# arr# off# addr len# s0 of
                    s1 -> case unIO (updatePtr @a ctx ptr (I# len#)) s1 of
                        (# s2, ctx' #) -> (# s2, ctx' #)
      where
        size# = sizeofByteArray# arr#
        contAddr = plusAddr# (byteArrayContents# arr#) off#
    {-# INLINEABLE update# #-}

    -- | Finalize a hash computation and return the digest.
    --
    finalize :: Context a -> a

    {-# MINIMAL (updatePtr | update#), finalize #-}

digestSize :: forall a n . IncrementalHash a => Num n => n
digestSize = fromIntegral $ natVal' @(DigestSize a) proxy#
{-# INLINE digestSize #-}

updateByteString
    :: forall a
    . IncrementalHash a
    => Context a
    -> B.ByteString
    -> Context a
updateByteString !ctx !b = unsafeDupablePerformIO $!
    B.unsafeUseAsCStringLen b $ \(!p, !l) -> updatePtr @a ctx (castPtr p) l
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
updateShortByteString !ctx !(BS.SBS b#) = unsafeDupablePerformIO $!
    update# @a ctx b# 0# (sizeofByteArray# b#)
{-# INLINE updateShortByteString #-}

updateStorable
    :: forall a b
    . IncrementalHash a
    => Storable b
    => Context a
    -> b
    -> Context a
updateStorable !ctx b = unsafeDupablePerformIO $!
    with b $ \p -> updatePtr @a ctx (castPtr p) (sizeOf b)
{-# INLINE updateStorable #-}

updateByteArray
    :: forall a
    . IncrementalHash a
    => Context a
    -> ByteArray
    -> Context a
updateByteArray ctx !(ByteArray b#) = unsafeDupablePerformIO $!
    update# @a ctx b# 0# (sizeofByteArray# b#)
{-# INLINE updateByteArray #-}

