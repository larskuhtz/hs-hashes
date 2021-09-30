{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UnboxedTuples #-}

-- |
-- Module: Data.Hash.FNV1
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- The primitive versions are usually not more efficient than the version with
-- explicit word sizes for the respective host architecture.
--
module Data.Hash.FNV1
(
-- * IO API (64 bit)

  fnv1_64
, fnv1_64_
, fnv1a_64
, fnv1a_64_

-- * 32 bit versions
, fnv1_32
, fnv1_32_
, fnv1a_32
, fnv1a_32_

-- * Primitive (host word size)
, fnv1
, fnv1_
, fnv1Primitive
, fnv1Primitive_

, fnv1a
, fnv1a_
, fnv1aPrimitive
, fnv1aPrimitive_

-- * Utils
, module Data.Hash.Utils

-- * Constants
, fnvPrime
, fnvPrime32
, fnvPrime64

, fnvOffsetBasis
, fnvOffsetBasis32
, fnvOffsetBasis64

) where

import Data.Bits
import Data.Word

import Foreign.Ptr
import Foreign.Storable

import GHC.Exts

import GHC.IO

-- internal modules

import Data.Hash.Utils

-- -------------------------------------------------------------------------- --
-- Constants

fnvPrime32 :: Word32
fnvPrime32 = 0x01000193

fnvPrime64 :: Word64
fnvPrime64 = 0x100000001b3

fnvOffsetBasis32 :: Word32
fnvOffsetBasis32 = 0x811c9dc5

fnvOffsetBasis64 :: Word64
fnvOffsetBasis64 = 0xcbf29ce484222325

fnvPrime :: Word
#if defined(x86_64_HOST_ARCH)
fnvPrime = fromIntegral fnvPrime64
#elif defined(i386_HOST_ARCH)
fnvPrime = fromIntegral fvnPrime32
#else
fnvPrime = error "fnvPrime: unsupported hardware platform"
#endif

fnvOffsetBasis :: Word
#if defined(x86_64_HOST_ARCH)
fnvOffsetBasis = fromIntegral fnvOffsetBasis64
#elif defined(i386_HOST_ARCH)
fnvOffsetBasis = fromIntegral fnvOffsetBasis32
#else
fnvOffsetBasis = error "fnvOffsetBasis: unsupported hardware platform"
#endif

-- -------------------------------------------------------------------------- --
-- FNV1 64 bit

fnv1_64 :: Ptr Word8 -> Int -> IO Word64
fnv1_64 !ptr !n = fnv1_64_ ptr n fnvOffsetBasis64
{-# INLINE fnv1_64 #-}

fnv1_64_ :: Ptr Word8 -> Int -> Word64 -> IO Word64
fnv1_64_ !ptr !n !a = loop a 0
  where
    loop !acc !i
        | i == n = return acc
        | otherwise = do
            !x <- peekByteOff @Word8 ptr i
            loop ((fnvPrime64 * acc) `xor` fromIntegral x) (i + 1)
{-# INLINE fnv1_64_ #-}

-- -------------------------------------------------------------------------- --
-- FNV1a 64 bit

fnv1a_64 :: Ptr Word8 -> Int -> IO Word64
fnv1a_64 !ptr !n = fnv1a_64_ ptr n fnvOffsetBasis64
{-# INLINE fnv1a_64 #-}

fnv1a_64_ :: Ptr Word8 -> Int -> Word64 -> IO Word64
fnv1a_64_ !ptr !n !a = loop a 0
  where
    loop !acc !i
        | i == n = return acc
        | otherwise = do
            !x <- peekByteOff @Word8 ptr i
            loop (fnvPrime64 * (acc `xor` fromIntegral x)) (i + 1)
{-# INLINE fnv1a_64_ #-}

-- -------------------------------------------------------------------------- --
-- FNV1 32 bit

fnv1_32 :: Ptr Word8 -> Int -> IO Word32
fnv1_32 !ptr !n = fnv1_32_ ptr n fnvOffsetBasis32
{-# INLINE fnv1_32 #-}

fnv1_32_ :: Ptr Word8 -> Int -> Word32 -> IO Word32
fnv1_32_ !ptr !n !a = loop a 0
  where
    loop !acc !i
        | i == n = return acc
        | otherwise = do
            !x <- peekByteOff @Word8 ptr i
            loop ((fnvPrime32 * acc) `xor` fromIntegral x) (i + 1)
{-# INLINE fnv1_32_ #-}

-- FNV1a 32 bit

fnv1a_32 :: Ptr Word8 -> Int -> IO Word32
fnv1a_32 !ptr !n = fnv1a_32_ ptr n fnvOffsetBasis32
{-# INLINE fnv1a_32 #-}

fnv1a_32_ :: Ptr Word8 -> Int -> Word32 -> IO Word32
fnv1a_32_ !ptr !n a = loop a 0
  where
    loop !acc !i
        | i == n = return acc
        | otherwise = do
            !x <- peekByteOff @Word8 ptr i
            loop (fnvPrime32 * (acc `xor` fromIntegral x)) (i + 1)
{-# INLINE fnv1a_32_ #-}

-- -------------------------------------------------------------------------- --
-- Primitive (host architecture words)

-- FNV1

fnv1 :: Addr# -> Int -> IO Word
fnv1 addr (I# n) = IO $ \s -> case fnv1Primitive addr n s of
    (# s1, w #) -> (# s1, W# w #)
{-# INlINE fnv1 #-}

fnv1_ :: Addr# -> Int -> Word -> IO Word
fnv1_ addr (I# n) (W# a) = IO $ \s -> case fnv1Primitive_ addr n a s of
    (# s1, w #) -> (# s1, W# w #)
{-# INlINE fnv1_ #-}

fnv1Primitive :: Addr# -> Int# -> State# tok -> (# State# tok, Word# #)
fnv1Primitive !addr !n !tok = fnv1Primitive_ addr n o tok
  where
    !(W# o) = fnvOffsetBasis
{-# INLINE fnv1Primitive #-}

fnv1Primitive_ :: Addr# -> Int# -> Word# -> State# tok -> (# State# tok, Word# #)
fnv1Primitive_ !addr !n !a tok = case loop a 0# tok of
    (# tok1, w #) -> (# tok1, w #)
  where
    loop !acc !i !s = case i ==# n of
        1# -> (# s, acc #)
        _ -> case readWord8OffAddr# addr i s of
            (# s1, w #) -> loop
                ((p `timesWord#` acc) `xor#` word8ToWord# w)
                (i +# 1#)
                s1

    !(W# p) = fnvPrime
{-# INLINE fnv1Primitive_ #-}

-- FNV1a

fnv1a :: Addr# -> Int -> IO Word
fnv1a addr (I# n) = IO $ \s -> case fnv1aPrimitive addr n s of
    (# s1, w #) -> (# s1, W# w #)
{-# INlINE fnv1a #-}

fnv1a_ :: Addr# -> Int -> Word -> IO Word
fnv1a_ addr (I# n) (W# a) = IO $ \s -> case fnv1aPrimitive_ addr n a s of
    (# s1, w #) -> (# s1, W# w #)
{-# INlINE fnv1a_ #-}

fnv1aPrimitive :: Addr# -> Int# -> State# tok -> (# State# tok, Word# #)
fnv1aPrimitive !addr !n !tok = fnv1aPrimitive_ addr n o tok
  where
    !(W# o) = fnvOffsetBasis
{-# INLINE fnv1aPrimitive #-}

fnv1aPrimitive_ :: Addr# -> Int# -> Word# -> State# tok -> (# State# tok, Word# #)
fnv1aPrimitive_ !addr !n !a tok = case loop a 0# tok of
    (# tok1, w #) -> (# tok1, w #)
  where
    loop !acc !i !s = case i ==# n of
        1# -> (# s, acc #)
        _ -> case readWord8OffAddr# addr i s of
            (# s1, w #) -> loop
                (p `timesWord#` (acc `xor#` word8ToWord# w))
                (i +# 1#)
                s1

    !(W# p) = fnvPrime
{-# INLINE fnv1aPrimitive_ #-}

-- -------------------------------------------------------------------------- --
-- Backward compatibility

#if !MIN_VERSION_base(4,16,0)
-- | 'readWord8OffAddr#' returns 'Word#' for base < 4.16.0. So, there's no
-- need to convert it to 'Word#' down the road.
--
word8ToWord# :: Word# -> Word#
word8ToWord# a = a
#endif
