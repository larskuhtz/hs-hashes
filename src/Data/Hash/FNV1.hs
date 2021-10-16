{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
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
-- * Fnv1 64 bit
  Fnv164Hash(..)
, Fnv164Context
, fnv164Initialize
, fnv164Update
, fnv164Finalize
, fnv164


-- * Fnv1a 64 bit
, Fnv1a64Hash(..)
, Fnv1a64Context
, fnv1a64Initialize
, fnv1a64Update
, fnv1a64Finalize
, fnv1a64

-- * Fnv1 32 bit
, Fnv132Hash(..)
, Fnv132Context
, fnv132Initialize
, fnv132Update
, fnv132Finalize
, fnv132

-- * Fnv1a 32 bit
, Fnv1a32Hash(..)
, Fnv1a32Context
, fnv1a32Initialize
, fnv1a32Update
, fnv1a32Finalize
, fnv1a32

-- * Fnv1 Host Wordsize
, Fnv1Hash(..)
, Fnv1Context
, fnv1Initialize
, fnv1Update
, fnv1Finalize
, fnv1

-- * Fnv1a Host Wordsize
, Fnv1aHash(..)
, Fnv1aContext
, fnv1aInitialize
, fnv1aUpdate
, fnv1aFinalize
, fnv1a

-- * Utils
, module Data.Hash.Class.Pure

-- * Low-Level
-- ** 64 bit

, fnv1_64
, fnv1_64_
, fnv1a_64
, fnv1a_64_

-- ** 32 bit
, fnv1_32
, fnv1_32_
, fnv1a_32
, fnv1a_32_

-- ** Host word size
, fnv1_host
, fnv1_host_
, fnv1Primitive
, fnv1Primitive_

, fnv1a_host
, fnv1a_host_
, fnv1aPrimitive
, fnv1aPrimitive_

-- ** Internal Constants
, fnvPrime
, fnvPrime32
, fnvPrime64

, fnvOffsetBasis
, fnvOffsetBasis32
, fnvOffsetBasis64

) where

import Control.Monad

import Data.Bits
import Data.Word

import Foreign.Ptr
import Foreign.Storable

import GHC.Exts
import GHC.IO

-- internal modules

import Data.Hash.Class.Pure

-- -------------------------------------------------------------------------- --
-- Fnv1 64 bit

newtype Fnv164Context = Fnv164Context Word64

newtype Fnv164Hash = Fnv164Hash Word64
    deriving (Show, Eq, Ord)

fnv164Initialize :: Fnv164Context
fnv164Initialize = Fnv164Context fnvOffsetBasis64
{-# INLINE fnv164Initialize #-}

fnv164Update :: Fnv164Context -> Ptr Word8 -> Int -> IO Fnv164Context
fnv164Update (Fnv164Context !ctx) !ptr !n =
    Fnv164Context <$!> fnv1_64_ ptr n ctx
{-# INLINE fnv164Update #-}

fnv164Finalize :: Fnv164Context -> Fnv164Hash
fnv164Finalize (Fnv164Context !ctx) = Fnv164Hash ctx
{-# INLINE fnv164Finalize #-}

fnv164 :: Ptr Word8 -> Int -> IO Fnv164Hash
fnv164 !ptr !n = fnv164Finalize <$!> fnv164Update fnv164Initialize ptr n
{-# INLINE fnv164 #-}

instance IncrementalHash Fnv164Hash where
    type Context Fnv164Hash = Fnv164Context
    update = fnv164Update
    finalize = fnv164Finalize

    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance Hash Fnv164Hash where
    initialize = fnv164Initialize
    {-# INLINE initialize #-}

-- -------------------------------------------------------------------------- --
-- Fnv1a 64 bit

newtype Fnv1a64Context = Fnv1a64Context Word64

newtype Fnv1a64Hash = Fnv1a64Hash Word64
    deriving (Show, Eq, Ord)

fnv1a64Initialize :: Fnv1a64Context
fnv1a64Initialize = Fnv1a64Context fnvOffsetBasis64
{-# INLINE fnv1a64Initialize #-}

fnv1a64Update :: Fnv1a64Context -> Ptr Word8 -> Int -> IO Fnv1a64Context
fnv1a64Update (Fnv1a64Context !ctx) !ptr !n =
    Fnv1a64Context <$!> fnv1a_64_ ptr n ctx
{-# INLINE fnv1a64Update #-}

fnv1a64Finalize :: Fnv1a64Context -> Fnv1a64Hash
fnv1a64Finalize (Fnv1a64Context !ctx) = Fnv1a64Hash ctx
{-# INLINE fnv1a64Finalize #-}

fnv1a64 :: Ptr Word8 -> Int -> IO Fnv1a64Hash
fnv1a64 !ptr !n = fnv1a64Finalize <$!> fnv1a64Update fnv1a64Initialize ptr n
{-# INLINE fnv1a64 #-}

instance IncrementalHash Fnv1a64Hash where
    type Context Fnv1a64Hash = Fnv1a64Context
    update = fnv1a64Update
    finalize = fnv1a64Finalize

    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance Hash Fnv1a64Hash where
    initialize = fnv1a64Initialize
    {-# INLINE initialize #-}

-- -------------------------------------------------------------------------- --
-- Fnv1 32 bit

newtype Fnv132Context = Fnv132Context Word32

newtype Fnv132Hash = Fnv132Hash Word32
    deriving (Show, Eq, Ord)

fnv132Initialize :: Fnv132Context
fnv132Initialize = Fnv132Context fnvOffsetBasis32
{-# INLINE fnv132Initialize #-}

fnv132Update :: Fnv132Context -> Ptr Word8 -> Int -> IO Fnv132Context
fnv132Update (Fnv132Context !ctx) !ptr !n =
    Fnv132Context <$!> fnv1_32_ ptr n ctx
{-# INLINE fnv132Update #-}

fnv132Finalize :: Fnv132Context -> Fnv132Hash
fnv132Finalize (Fnv132Context !ctx) = Fnv132Hash ctx
{-# INLINE fnv132Finalize #-}

fnv132 :: Ptr Word8 -> Int -> IO Fnv132Hash
fnv132 !ptr !n = fnv132Finalize <$!> fnv132Update fnv132Initialize ptr n
{-# INLINE fnv132 #-}

instance IncrementalHash Fnv132Hash where
    type Context Fnv132Hash = Fnv132Context
    update = fnv132Update
    finalize = fnv132Finalize

    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance Hash Fnv132Hash where
    initialize = fnv132Initialize
    {-# INLINE initialize #-}

-- -------------------------------------------------------------------------- --
-- Fnv1a 32 bit

newtype Fnv1a32Context = Fnv1a32Context Word32

newtype Fnv1a32Hash = Fnv1a32Hash Word32
    deriving (Show, Eq, Ord)

fnv1a32Initialize :: Fnv1a32Context
fnv1a32Initialize = Fnv1a32Context fnvOffsetBasis32
{-# INLINE fnv1a32Initialize #-}

fnv1a32Update :: Fnv1a32Context -> Ptr Word8 -> Int -> IO Fnv1a32Context
fnv1a32Update (Fnv1a32Context !ctx) !ptr !n =
    Fnv1a32Context <$!> fnv1a_32_ ptr n ctx
{-# INLINE fnv1a32Update #-}

fnv1a32Finalize :: Fnv1a32Context -> Fnv1a32Hash
fnv1a32Finalize (Fnv1a32Context !ctx) = Fnv1a32Hash ctx
{-# INLINE fnv1a32Finalize #-}

fnv1a32 :: Ptr Word8 -> Int -> IO Fnv1a32Hash
fnv1a32 !ptr !n = fnv1a32Finalize <$!> fnv1a32Update fnv1a32Initialize ptr n
{-# INLINE fnv1a32 #-}

instance IncrementalHash Fnv1a32Hash where
    type Context Fnv1a32Hash = Fnv1a32Context
    update = fnv1a32Update
    finalize = fnv1a32Finalize

    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance Hash Fnv1a32Hash where
    initialize = fnv1a32Initialize
    {-# INLINE initialize #-}

-- -------------------------------------------------------------------------- --
-- Fnv1 Host Wordsize

newtype Fnv1Context = Fnv1Context Word

newtype Fnv1Hash = Fnv1Hash Word
    deriving (Show, Eq, Ord)

fnv1Initialize :: Fnv1Context
fnv1Initialize = Fnv1Context fnvOffsetBasis
{-# INLINE fnv1Initialize #-}

fnv1Update :: Fnv1Context -> Ptr Word8 -> Int -> IO Fnv1Context
fnv1Update (Fnv1Context !ctx) !ptr !n =
    Fnv1Context <$!> fnv1_host_ ptr n ctx
{-# INLINE fnv1Update #-}

fnv1Finalize :: Fnv1Context -> Fnv1Hash
fnv1Finalize (Fnv1Context !ctx) = Fnv1Hash ctx
{-# INLINE fnv1Finalize #-}

fnv1 :: Ptr Word8 -> Int -> IO Fnv1Hash
fnv1 !ptr !n = fnv1Finalize <$!> fnv1Update fnv1Initialize ptr n
{-# INLINE fnv1 #-}

instance IncrementalHash Fnv1Hash where
    type Context Fnv1Hash = Fnv1Context
    update = fnv1Update
    finalize = fnv1Finalize

    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance Hash Fnv1Hash where
    initialize = fnv1Initialize
    {-# INLINE initialize #-}

-- -------------------------------------------------------------------------- --
-- Fnv1a Host Wordsize

newtype Fnv1aContext = Fnv1aContext Word

newtype Fnv1aHash = Fnv1aHash Word
    deriving (Show, Eq, Ord)

fnv1aInitialize :: Fnv1aContext
fnv1aInitialize = Fnv1aContext fnvOffsetBasis
{-# INLINE fnv1aInitialize #-}

fnv1aUpdate :: Fnv1aContext -> Ptr Word8 -> Int -> IO Fnv1aContext
fnv1aUpdate (Fnv1aContext !ctx) !ptr !n =
    Fnv1aContext <$!> fnv1a_host_ ptr n ctx
{-# INLINE fnv1aUpdate #-}

fnv1aFinalize :: Fnv1aContext -> Fnv1aHash
fnv1aFinalize (Fnv1aContext !ctx) = Fnv1aHash ctx
{-# INLINE fnv1aFinalize #-}

fnv1a :: Ptr Word8 -> Int -> IO Fnv1aHash
fnv1a !ptr !n = fnv1aFinalize <$!> fnv1aUpdate fnv1aInitialize ptr n
{-# INLINE fnv1a #-}

instance IncrementalHash Fnv1aHash where
    type Context Fnv1aHash = Fnv1aContext
    update = fnv1aUpdate
    finalize = fnv1aFinalize

    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance Hash Fnv1aHash where
    initialize = fnv1aInitialize
    {-# INLINE initialize #-}

-- -------------------------------------------------------------------------- --
-- Low Level
-- -------------------------------------------------------------------------- --

-- -------------------------------------------------------------------------- --
-- Constants

fnvPrime32 :: Word32
fnvPrime32 = 0x01000193
{-# INLINE fnvPrime32 #-}

fnvPrime64 :: Word64
fnvPrime64 = 0x100000001b3
{-# INLINE fnvPrime64 #-}

fnvOffsetBasis32 :: Word32
fnvOffsetBasis32 = 0x811c9dc5
{-# INLINE fnvOffsetBasis32 #-}

fnvOffsetBasis64 :: Word64
fnvOffsetBasis64 = 0xcbf29ce484222325
{-# INLINE fnvOffsetBasis64 #-}

fnvPrime :: Word
#if defined(x86_64_HOST_ARCH)
fnvPrime = fromIntegral fnvPrime64
#elif defined(i386_HOST_ARCH)
fnvPrime = fromIntegral fvnPrime32
#else
fnvPrime = error "fnvPrime: unsupported hardware platform"
#endif
{-# INLINE fnvPrime #-}

fnvOffsetBasis :: Word
#if defined(x86_64_HOST_ARCH)
fnvOffsetBasis = fromIntegral fnvOffsetBasis64
#elif defined(i386_HOST_ARCH)
fnvOffsetBasis = fromIntegral fnvOffsetBasis32
#else
fnvOffsetBasis = error "fnvOffsetBasis: unsupported hardware platform"
#endif
{-# INLINE fnvOffsetBasis #-}

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
-- Host architecture words

-- FNV1

fnv1_host :: Ptr Word8 -> Int -> IO Word
fnv1_host (Ptr addr) (I# n) = IO $ \s -> case fnv1Primitive addr n s of
    (# s1, w #) -> (# s1, W# w #)
{-# INlINE fnv1_host #-}

fnv1_host_ :: Ptr Word8 -> Int -> Word -> IO Word
fnv1_host_ (Ptr addr) (I# n) (W# a) = IO $ \s -> case fnv1Primitive_ addr n a s of
    (# s1, w #) -> (# s1, W# w #)
{-# INlINE fnv1_host_ #-}

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

-- -------------------------------------------------------------------------- --
-- Host Wordsize FNV1a

fnv1a_host :: Ptr Word8 -> Int -> IO Word
fnv1a_host (Ptr addr) (I# n) = IO $ \s -> case fnv1aPrimitive addr n s of
    (# s1, w #) -> (# s1, W# w #)
{-# INlINE fnv1a_host #-}

fnv1a_host_ :: Ptr Word8 -> Int -> Word -> IO Word
fnv1a_host_ (Ptr addr) (I# n) (W# a) = IO $ \s -> case fnv1aPrimitive_ addr n a s of
    (# s1, w #) -> (# s1, W# w #)
{-# INlINE fnv1a_host_ #-}

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
            (# s1, w #) ->
                let !acc' = p `timesWord#` (acc `xor#` word8ToWord# w)
                    !n' = i +# 1#
                in loop acc' n' s1

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
{-# INLINE word8ToWord# #-}
#endif
