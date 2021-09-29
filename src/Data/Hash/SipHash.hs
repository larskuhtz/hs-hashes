{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UnboxedTuples #-}

-- |
-- Module: Data.Hash.SipHash
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Data.Hash.SipHash
( sipHash
, sipHash13
, sipHash24
, sipHash48
, sipHashCD

-- * Utils
, module Data.Hash.Utils
) where

import Control.Monad

import Data.Bits
import Data.Function
import Data.Word

import Foreign.Marshal.Utils
import Foreign.Storable

import GHC.Ptr

import Prelude hiding (drop, length, null, splitAt, take)

-- internal modules

import Data.Hash.Utils

-- -------------------------------------------------------------------------- --
-- SipHash

-- | SipHash, with recommended default parameters of c=2 and c=4.
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHash
    :: Word64
    -> Word64
    -> Ptr Word8
    -> Int
    -> IO Word64
sipHash = sipHash24
{-# INLINE sipHash #-}

-- | SipHash-2-4
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHash24
    :: Word64
    -> Word64
    -> Ptr Word8
    -> Int
    -> IO Word64
sipHash24 = sipHashInternal rounds2 rounds4
{-# INLINE sipHash24 #-}

-- | SipHash-1-3
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHash13
    :: Word64
    -> Word64
    -> Ptr Word8
    -> Int
    -> IO Word64
sipHash13 = sipHashInternal rounds1 rounds3
{-# INLINE sipHash13 #-}

-- | SipHash-4-8
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHash48
    :: Word64
    -> Word64
    -> Ptr Word8
    -> Int
    -> IO Word64
sipHash48 = sipHashInternal rounds4 rounds8
{-# INLINE sipHash48 #-}

-- | Generic SipHash with c rounds per block and d finalization rounds.
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHashCD
    :: Int
    -> Int
    -> Word64
    -> Word64
    -> Ptr Word8
    -> Int
    -> IO Word64
sipHashCD c d = sipHashInternal (rounds c) (rounds d)
{-# INLINE sipHashCD #-}

-- -------------------------------------------------------------------------- --
-- Generic SipHash

data S = S
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64

type Round = Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)

sipHashInternal
    :: Round
    -> Round
    -> Word64
    -> Word64
    -> Ptr Word8
    -> Int
    -> IO Word64
sipHashInternal cRound dRound !k0 !k1 !ptr !len = do

    -- loop
    (S !v0 !v1 !v2 !v3) <- loop i0 i1 i2 i3 (castPtr ptr) len

    -- end
    let (!off, !r) = quotRem len 8
    w <- ptrToWord64 (plusPtr ptr (off * 8)) r
    let !b = shiftL (fromIntegral len) 56 .|. w
        (# !v0', !v1', !v2', !v3' #) = cRound v0 v1 v2 (v3 `xor` b)
        (# !v0'', !v1'', !v2'', !v3'' #) = dRound (v0' `xor` b) v1' (v2' `xor` 0xff) v3'
    return $! v0'' `xor` v1'' `xor` v2'' `xor` v3''

  where

    loop !v0 !v1 !v2 !v3 !p !l
        | l < 8 = return $ S v0 v1 v2 v3
        | otherwise = do
            !m <- peek p
            let (# v0', v1', v2', v3' #) = cRound v0 v1 v2 (v3 `xor` m)
            loop (v0' `xor` m) v1' v2' v3' (plusPtr p 8) (l - 8)

    !i0 = 0x736f6d6570736575 `xor` k0
    !i1 = 0x646f72616e646f6d `xor` k1
    !i2 = 0x6c7967656e657261 `xor` k0
    !i3 = 0x7465646279746573 `xor` k1
    {-# INLINE i0 #-}
    {-# INLINE i1 #-}
    {-# INLINE i2 #-}
    {-# INLINE i3 #-}
{-# INLINE sipHashInternal #-}

ptrToWord64 :: Ptr Word64 -> Int -> IO Word64
ptrToWord64 _ 0 = pure 0
ptrToWord64 !p 1 = fromIntegral <$!> peek @Word8 (castPtr p)
ptrToWord64 !p 2 = fromIntegral <$!> peek @Word16 (castPtr p)
ptrToWord64 !p 4 = fromIntegral <$!> peek @Word32 (castPtr p)
ptrToWord64 !p !i = with @Word64 0 $ \p' -> do
        -- using 'with' within unsafeDupablePerformIO is probably safe because
        -- with uses 'alloca', which guarantees that the memory is released
        -- when computation is abondended before being terminated.
    copyBytes p' p i
    peek p'
{-# INLINE ptrToWord64 #-}

rounds1 :: Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)
rounds1 !v0 !v1 !v2 !v3 = sipRound v0 v1 v2 v3
{-# INLINE rounds1 #-}

rounds2 :: Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)
rounds2 !v0 !v1 !v2 !v3 =
    let (# !v0', !v1', !v2', !v3' #) = sipRound v0 v1 v2 v3
    in sipRound v0' v1' v2' v3'
{-# INLINE rounds2 #-}

rounds3 :: Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)
rounds3 !v0 !v1 !v2 !v3 =
    let (# !v0', !v1', !v2', !v3' #) = sipRound v0 v1 v2 v3
        (# !v0'', !v1'', !v2'', !v3'' #) = sipRound v0' v1' v2' v3'
    in sipRound v0'' v1'' v2'' v3''
{-# INLINE rounds3 #-}

rounds4 :: Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)
rounds4 !v0 !v1 !v2 !v3 =
    let (# !v0', !v1', !v2', !v3' #) = sipRound v0 v1 v2 v3
        (# !v0'', !v1'', !v2'', !v3'' #) = sipRound v0' v1' v2' v3'
        (# !v0''', !v1''', !v2''', !v3''' #) = sipRound v0'' v1'' v2'' v3''
    in sipRound v0''' v1''' v2''' v3'''
{-# INLINE rounds4 #-}

rounds8 :: Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)
rounds8 !v0 !v1 !v2 !v3 =
    let (# !v0', !v1', !v2', !v3' #) = sipRound v0 v1 v2 v3
        (# !v0'', !v1'', !v2'', !v3'' #) = sipRound v0' v1' v2' v3'
        (# !v0''', !v1''', !v2''', !v3''' #) = sipRound v0'' v1'' v2'' v3''
        (# !v0'''', !v1'''', !v2'''', !v3'''' #) = sipRound v0''' v1''' v2''' v3'''
        (# !v0''''', !v1''''', !v2''''', !v3''''' #) = sipRound v0'''' v1'''' v2'''' v3''''
        (# !v0'''''', !v1'''''', !v2'''''', !v3'''''' #) = sipRound v0''''' v1''''' v2''''' v3'''''
        (# !v0''''''', !v1''''''', !v2''''''', !v3''''''' #) = sipRound v0'''''' v1'''''' v2'''''' v3''''''
    in sipRound v0''''''' v1''''''' v2''''''' v3'''''''
{-# INLINE rounds8 #-}

rounds :: Int -> Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)
rounds 1 !v0 !v1 !v2 !v3 = rounds1 v0 v1 v2 v3
rounds 2 !v0 !v1 !v2 !v3 = rounds2 v0 v1 v2 v3
rounds 3 !v0 !v1 !v2 !v3 = rounds3 v0 v1 v2 v3
rounds 4 !v0 !v1 !v2 !v3 = rounds4 v0 v1 v2 v3
rounds 8 !v0 !v1 !v2 !v3 = rounds8 v0 v1 v2 v3
rounds !c !v0 !v1 !v2 !v3 = case sipRound v0 v1 v2 v3 of
    (# v0', v1', v2', v3' #) -> rounds (c - 1) v0' v1' v2' v3'
{-# INLINE rounds #-}

sipRound :: Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)
sipRound !v0 !v1 !v2 !v3 = (# v0''', v1'''', v2''', v3'''' #)
    where
    !v0' = v0 + v1
    !v2' = v2 + v3
    !v1' = v1 `rotateL` 13
    !v3' = v3 `rotateL` 16
    !v1'' = v1' `xor` v0'
    !v3'' = v3' `xor` v2'
    !v0'' = v0' `rotateL` 32
    !v2'' = v2' + v1''
    !v0''' = v0'' + v3''
    !v1''' = v1'' `rotateL` 17
    !v3''' = v3'' `rotateL` 21
    !v1'''' = v1''' `xor` v2''
    !v3'''' = v3''' `xor` v0'''
    !v2''' = v2'' `rotateL` 32
{-# INLINE sipRound #-}

