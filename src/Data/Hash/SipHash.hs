{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE UndecidableInstances #-}

-- |
-- Module: Data.Hash.SipHash
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Data.Hash.SipHash
( SipHashKey(..)
, SipHash(..)
, sipHash

-- * SipHash-c-d
, sipHashCD
, sipHash24
, sipHash13
, sipHash48

-- * Incremental SipHash
, SipHashContext
, sipHashInitialize
, sipHashUpdate
, sipHashFinalize

-- * Utils
, module Data.Hash.Class.Pure.Salted
) where

import Control.Monad

import Data.Bits
import Data.Type.Equality
import Data.Word

import Foreign.Marshal
import Foreign.Ptr
import Foreign.Storable

import GHC.TypeNats

-- internal modules

import Data.Hash.Class.Pure.Salted

-- -------------------------------------------------------------------------- --
-- SipHash

-- | SipHash, with recommended default parameters of c=2 and d=4.
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHash
    :: SipHashKey
    -> Ptr Word8
    -> Int
    -> IO (SipHash 2 4)
sipHash = sipHashCD
{-# INLINE sipHash #-}

-- | Generic SipHash with c rounds per block and d finalization rounds.
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHashCD
    :: forall c d
    . SipHashParam c
    => SipHashParam d
    => SipHashKey
    -> Ptr Word8
    -> Int
    -> IO (SipHash c d)
sipHashCD key ptr n = sipHashFinalize
    <$> sipHashUpdate (sipHashInitialize key) ptr n
{-# INLINE sipHashCD #-}

-- | SipHash-2-4
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHash24 :: SipHashKey -> Ptr Word8 -> Int -> IO (SipHash 2 4)
sipHash24 = sipHashCD
{-# INLINE sipHash24 #-}

-- | SipHash-1-3
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHash13 :: SipHashKey -> Ptr Word8 -> Int -> IO (SipHash 1 3)
sipHash13 = sipHashCD
{-# INLINE sipHash13 #-}

-- | SipHash-4-8
--
-- The first and second argument is the 128 bit key, represented as two 64 bit
-- words.
--
sipHash48 :: SipHashKey -> Ptr Word8 -> Int -> IO (SipHash 4 8)
sipHash48 = sipHashCD
{-# INLINE sipHash48 #-}

-- -------------------------------------------------------------------------- --
-- Class

instance (SipHashParam c, SipHashParam d) => IncrementalHash (SipHash c d) where
    type Context (SipHash c d) = SipHashContext c d
    update = sipHashUpdate
    finalize = sipHashFinalize

    {-# INLINE update #-}
    {-# INLINE finalize #-}

instance (SipHashParam c, SipHashParam d) => Hash (SipHash c d) where
    type Salt (SipHash c d) = SipHashKey
    initialize = sipHashInitialize
    {-# INLINE initialize #-}

-- -------------------------------------------------------------------------- --
-- Incremental Version of SipHash

-- | SipHash with @c@ compression rounds and @d@ finalization rounds.
--
-- cf. http://cr.yp.to/siphash/siphash-20120918.pdf
--
newtype SipHash (c :: Nat) (d :: Nat) = SipHash Word64
    deriving (Show, Eq, Ord)

-- | The 'Word46' constructor parameters represent the 128 bit key in little
-- endian encoding.
--
data SipHashKey = SipHashKey {-# UNPACK #-} !Word64 {-# UNPACK #-} !Word64
    deriving (Show, Eq, Ord)

-- | Internal mutable SipHashContext.
--
-- The first four arguments are the internal state values \(v_{0..3}\) and the
-- last argument represents the pending bytes from an incomplete word of the
-- last chunk of input.
--
data SipHashContext (c :: Nat) (d :: Nat) = SipHashContext
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
        -- ^ the most significant byte keeps track of the total number of input
        -- bytes modulo 256. The remaining bytes are the currently pending input
        -- bytes (i.e. the last \(totalInput `mod` 8\) many bytes of the input).

-- | Initialize a new SipHashContext
--
sipHashInitialize :: SipHashKey -> SipHashContext c d
sipHashInitialize (SipHashKey k0 k1) = SipHashContext
    (0x736f6d6570736575 `xor` k0)
    (0x646f72616e646f6d `xor` k1)
    (0x6c7967656e657261 `xor` k0)
    (0x7465646279746573 `xor` k1)
    0x0
{-# INLINE sipHashInitialize #-}

-- | Incrementally add input bytes to an SipHash computation and update
-- the internal context.
--
sipHashUpdate
    :: forall (c :: Nat) (d :: Nat)
    . SipHashParam c
    => SipHashContext c d
    -> Ptr Word8
    -> Int
    -> IO (SipHashContext c d)
sipHashUpdate (SipHashContext s0 s1 s2 s3 r) ptr8 len
    | 0 <- rlen `rem` 8 = loop s0 s1 s2 s3 ptr64 len64

    -- Consume the first input word using any possibly pending input bytes from
    -- previous updates.
    --
    | a <- rlen `rem` 8 = do
        let !missing = 8 - a

        -- get enough bytes to fill up next word (if there are less than 8 - a
        -- bytes the most significant bytes are set to 0)
        !m <- ptrToWord64 ptr64 $ fromIntegral missing

        -- add new bytes to get full word64. Input is parsed as little endian,
        -- so new bytes are more significant than pending bytes.
        let !m' = (0x00ffffffffffffff .&. r {- pending bytes -}) .|. m

        if len64 < missing
          then
            -- nothing left to do
            return $ SipHashContext s0 s1 s2 s3 (shiftL (rlen + len64) 56 .|. m')
          else do
            -- compute c round with first word
            let (# v0', v1', v2', v3' #) = rounds @c s0 s1 s2 (s3 `xor` m')
            loop (v0' `xor` m') v1' v2' v3' (plusPtr ptr64 (fromIntegral missing)) (len64 - missing)
  where
    len64 = fromIntegral len
    {-# INLINE len64 #-}

    !ptr64 = castPtr ptr8
    {-# INLINE ptr64 #-}

    !rlen = 0xff00000000000000 .&. r
    {-# INLINE rlen #-}


    -- Assumes that there are no pending bytes.
    loop !v0 !v1 !v2 !v3 !p !l
        | l < 8 = do
            !m <- ptrToWord64 p l
            return $ SipHashContext v0 v1 v2 v3 (shiftL (rlen + len64) 56 .|. m)
        | otherwise = do
            -- TODO enforce little endian encoding
            !m <- peek p
            let (# v0', v1', v2', v3' #) = rounds @c v0 v1 v2 (v3 `xor` m)
            loop (v0' `xor` m) v1' v2' v3' (plusPtr p 8) (l - 8)
    {-# INLINE loop #-}
{-# INLINE sipHashUpdate #-}

sipHashFinalize
    :: forall (c :: Nat) (d :: Nat)
    . SipHashParam c
    => SipHashParam d
    => SipHashContext c d
    -> SipHash c d
sipHashFinalize (SipHashContext v0 v1 v2 v3 m) =
    SipHash $! v0'' `xor` v1'' `xor` v2'' `xor` v3''
  where
    (# !v0', !v1', !v2', !v3' #) = rounds @c v0 v1 v2 (v3 `xor` m)
    (# !v0'', !v1'', !v2'', !v3'' #) = rounds @d (v0' `xor` m) v1' (v2' `xor` 0xff) v3'
{-# INLINE sipHashFinalize #-}

ptrToWord64 :: Ptr Word64 -> Word64 -> IO Word64
ptrToWord64 _ 0 = pure 0
ptrToWord64 !p 1 = fromIntegral <$!> peek @Word8 (castPtr p)
ptrToWord64 !p 2 = fromIntegral <$!> peek @Word16 (castPtr p)
ptrToWord64 !p 4 = fromIntegral <$!> peek @Word32 (castPtr p)
ptrToWord64 !p !i = with @Word64 0 $ \p' -> do
        -- using 'with' within unsafeDupablePerformIO is probably safe because
        -- with uses 'alloca', which guarantees that the memory is released
        -- when computation is abondended before being terminated.
    copyBytes p' p (fromIntegral i)
    peek p'
{-# INLINE ptrToWord64 #-}

class SipHashParam (n :: Nat) where
    rounds :: Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)

instance SipHashRounds n (SlowRounds n) => SipHashParam (n :: Nat) where
    rounds = rounds_ @n @(SlowRounds n)
    {-# INLINE rounds #-}

-- -------------------------------------------------------------------------- --
-- SipHash Rounds

-- Decide wether to pick an fast specialized routes implementation or a somewhat
-- less efficient generic implementation.
--
type SlowRounds r = CmpNat r 8 == 'GT

-- TODO: create benchmark to check how well inlining works for recursive type class function calls,
-- It's possibly, that we don't need all these specializations but inlining gets the job done all by
-- itself.

class SipHashRounds (n :: Nat) (x :: Bool) where
    rounds_ :: Word64 -> Word64 -> Word64 -> Word64 -> (# Word64, Word64, Word64, Word64 #)

instance SipHashRounds 1 'False where
    rounds_ !v0 !v1 !v2 !v3 = sipRound v0 v1 v2 v3
    {-# INLINE rounds_ #-}

instance SipHashRounds 2 'False where
    rounds_ !v0 !v1 !v2 !v3 =
        let (# !v0', !v1', !v2', !v3' #) = sipRound v0 v1 v2 v3
        in sipRound v0' v1' v2' v3'
    {-# INLINE rounds_ #-}

instance SipHashRounds 3 'False where
    rounds_ !v0 !v1 !v2 !v3 =
        let (# !v0', !v1', !v2', !v3' #) = sipRound v0 v1 v2 v3
            (# !v0'', !v1'', !v2'', !v3'' #) = sipRound v0' v1' v2' v3'
        in sipRound v0'' v1'' v2'' v3''
    {-# INLINE rounds_ #-}

instance SipHashRounds 4 'False where
    rounds_ !v0 !v1 !v2 !v3 =
        let (# !v0', !v1', !v2', !v3' #) = sipRound v0 v1 v2 v3
            (# !v0'', !v1'', !v2'', !v3'' #) = sipRound v0' v1' v2' v3'
            (# !v0''', !v1''', !v2''', !v3''' #) = sipRound v0'' v1'' v2'' v3''
        in sipRound v0''' v1''' v2''' v3'''
    {-# INLINE rounds_ #-}

instance SipHashRounds 5 'False where
    rounds_ !v0 !v1 !v2 !v3 = case rounds_ @4 @'False v0 v1 v2 v3 of
        (# v0', v1', v2', v3' #) -> rounds_ @1 @'False v0' v1' v2' v3'
    {-# INLINE rounds_ #-}

instance SipHashRounds 6 'False where
    rounds_ !v0 !v1 !v2 !v3 = case rounds_ @4 @'False v0 v1 v2 v3 of
        (# v0', v1', v2', v3' #) -> rounds_ @2 @'False v0' v1' v2' v3'
    {-# INLINE rounds_ #-}

instance SipHashRounds 7 'False where
    rounds_ !v0 !v1 !v2 !v3 = case rounds_ @4 @'False v0 v1 v2 v3 of
        (# v0', v1', v2', v3' #) -> rounds_ @3 @'False v0' v1' v2' v3'
    {-# INLINE rounds_ #-}

instance SipHashRounds 8 'False where
    rounds_ !v0 !v1 !v2 !v3 =
        let (# !v0', !v1', !v2', !v3' #) = sipRound v0 v1 v2 v3
            (# !v0'', !v1'', !v2'', !v3'' #) = sipRound v0' v1' v2' v3'
            (# !v0''', !v1''', !v2''', !v3''' #) = sipRound v0'' v1'' v2'' v3''
            (# !v0'''', !v1'''', !v2'''', !v3'''' #) = sipRound v0''' v1''' v2''' v3'''
            (# !v0''''', !v1''''', !v2''''', !v3''''' #) = sipRound v0'''' v1'''' v2'''' v3''''
            (# !v0'''''', !v1'''''', !v2'''''', !v3'''''' #) = sipRound v0''''' v1''''' v2''''' v3'''''
            (# !v0''''''', !v1''''''', !v2''''''', !v3''''''' #) = sipRound v0'''''' v1'''''' v2'''''' v3''''''
        in sipRound v0''''''' v1''''''' v2''''''' v3'''''''
    {-# INLINE rounds_ #-}

instance ((CmpNat n 8 == 'GT) ~ 'True, SipHashRounds (n-8) t) => SipHashRounds n 'True where
    rounds_ !v0 !v1 !v2 !v3 = case rounds_ @8 @'False v0 v1 v2 v3 of
        (# v0', v1', v2', v3' #) -> rounds_ @(n - 8) @t v0' v1' v2' v3'
    {-# INLINE rounds_ #-}

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


