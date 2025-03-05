{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UnboxedTuples #-}

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
, digestSize
, updateByteString
, updateByteStringLazy
, updateShortByteString
, updateStorable
, updateByteArray

-- * Resetable Hashes
, ResetableHash(..)
) where

import Control.Monad
import Control.Exception

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

-- -------------------------------------------------------------------------- --
-- Exceptions

newtype MutableHashException = MutableHashException String
    deriving (Show)

instance Exception MutableHashException

-- -------------------------------------------------------------------------- --
-- Incremental Mutable Hashes

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
            -- ^ The mutable hash context
        -> Ptr Word8
            -- ^ Pointer to the input data
        -> Int
            -- ^ The size of the input data in bytes
        -> IO ()
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
            -- ^ The mutable hash context
        -> ByteArray#
            -- ^ The (possibly unpinned) byte array with the input data
        -> Int#
            -- ^ The offset into the input byte array
        -> Int#
            -- ^ The size of the input data in bytes
        -> IO ()
    update# ctx arr# off# len# = do
        -- Assert that the addressed memory is within the input array
        when (isTrue# (size# <# off# +# len#)) $
            throwIO $ MutableHashException "input array to small"

        if isTrue# (isByteArrayPinned# arr#)
          then
            -- Pinned ByteArray. We have to keep it alive. We don't know how
            -- updatePtr is implemented. So just 'touch#' is not an option.
            IO $ \s0 -> keepAlive# arr# s0 $ \s1 ->
                case unIO (updatePtr @a ctx (Ptr contAddr) (I# len#)) s1 of
                    (# s2, () #) -> (# s2, () #)
          else
            -- Unpinned ByteArray, copy content to temporarily allocated memory
            allocaBytes (I# len#) $ \ptr@(Ptr addr) -> IO $ \s0 ->
                case copyByteArrayToAddr# arr# off# addr len# s0 of
                    s1 -> case unIO (updatePtr @a ctx ptr (I# len#)) s1 of
                        (# s2, () #) -> (# s2, () #)
      where
        size# = sizeofByteArray# arr#
        contAddr = plusAddr# (byteArrayContents# arr#) off#
    {-# INLINEABLE update# #-}

    -- | Finalize a hash computation and return the digest.
    --
    -- The default implementation is in terms of finalize# and requires that the
    -- type of the digest can be coerced from 'ByteArray'.
    --
    finalize
        :: Context a
            -- The mutable hash context
        -> IO a

    default finalize
        :: Coercible a ByteArray
        => Context a
        -> IO a
    finalize ctx = IO $ \s0 -> case newByteArray# size# s0 of
        (# s1, a# #) -> case unIO (finalize# @a ctx a# 0#) s1 of
            (# s2, () #) -> case unsafeFreezeByteArray# a# s2 of
                (# s3, b# #) -> (# s3, coerce (ByteArray b#) #)
      where
        !(I# size#) = digestSize @a
    {-# INLINEABLE finalize #-}

    -- | Finalize a hash computation and write the digest bytes to the given
    -- 'MutableByteArray#' at the given offset.
    --
    -- This API can be beneficial if many nested hashes are computed, for
    -- instance during verification of Merkle proofs.
    --
    -- It is the responsiblility of the caller to guarantee that the result
    -- array is large enough. Implementations may check and fail gracefully, but
    -- this is not required.
    --
    -- The default implementation is in terms of 'finalPtr' and has to copy the
    -- content of array in case it is unpinned. It also ensures that pinned
    -- arrays are kept alive as long as needed.
    --
    finalize#
        :: Context a
            -- ^ The mutable hash context
        -> MutableByteArray# RealWorld
            -- ^ A (possibly unpinned) mutable byte array into which the digest
            -- is written
        -> Int#
            -- ^ The offset in the byte array at which the digest is written
        -> IO ()

    finalize# ctx arr# offset# = do
        asize <- IO $ \s -> case getSizeofMutableByteArray# arr# s of
            (# s', n# #) -> (# s', I# (n# -# offset#) #)
        when (asize < size) $
            throwIO $ MutableHashException "output array to small for the digest"

        if isTrue# (isMutableByteArrayPinned# arr#)
          then
            IO $ \s0 -> keepAlive# arr# s0 $ \s1 ->
                case unIO (finalizePtr @a ctx (Ptr trgAddr#)) s1 of
                    (# s2, () #) -> (# s2, () #)

          else
            allocaBytes size $ \ptr@(Ptr addr) -> IO $ \s0 ->
                case unIO (finalizePtr @a ctx ptr) s0 of
                    (# s1, () #) -> case copyAddrToByteArray# addr arr# offset# size# s1 of
                        s2 -> (# s2, () #)
      where
        !size@(I# size#) = digestSize @a
        trgAddr# = plusAddr# (mutableByteArrayContents# arr#) offset#
    {-# INLINEABLE finalize# #-}

    -- | Finalize a hash computation and write the digest bytes to the given
    -- 'Ptr'.
    --
    -- It is the responsiblility of the caller to guarantee that there is enough
    -- allocated space availale at the given Ptr and the pointer remains valid
    -- during the operation. In particular, if the pointer points into the
    -- Haskell keep the memory must be pinned and kept alive.
    --
    -- The default implementation is in terms of 'finalize#' and copies the
    -- resulting digest bytes to the Ptr.
    --
    finalizePtr
        :: Context a
            -- ^ The mutable hash context
        -> Ptr Word8
            -- ^ Pointer to the memory location where the digest is written to
        -> IO ()
    finalizePtr ctx (Ptr addr#) = do
        IO $ \s0 -> case newByteArray# size# s0 of
            (# s1, a# #) -> case unIO (finalize# @a ctx a# 0#) s1 of
                (# s2, () #) -> case copyMutableByteArrayToAddr# a# 0# addr# size# s2 of
                    s3 -> (# s3, () #)
      where
        !(I# size#) = digestSize @a
    {-# INLINEABLE finalizePtr #-}

    {-# MINIMAL (updatePtr | update#), (finalize# | finalizePtr) #-}

digestSize :: forall a n . IncrementalHash a => Num n => n
digestSize = fromIntegral $ natVal' @(DigestSize a) proxy#
{-# INLINE digestSize #-}

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
updateShortByteString ctx !(BS.SBS b#) = update# @a ctx b# 0# (sizeofByteArray# b#)
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
updateByteArray ctx !(ByteArray b#) = update# @a ctx b# 0# (sizeofByteArray# b#)
{-# INLINE updateByteArray #-}

-- -------------------------------------------------------------------------- --
-- Class of Resetable Hashes

class IncrementalHash a => ResetableHash a where
    reset :: Context a -> IO ()

