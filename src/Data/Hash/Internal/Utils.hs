{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

-- |
-- Module: Data.Hash.Internal.Utils
-- Copyright: Copyright © 2021-2024 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Data.Hash.Internal.Utils
( B16ShortByteString(..)
, b16
) where

import Data.Bits
import Data.Char
import Data.String
import Data.ByteString qualified as B
import qualified Data.ByteString.Short as BS

import Text.Printf

-- -------------------------------------------------------------------------- --
-- Utils

newtype B16ShortByteString = B16ShortByteString
    { _unB16ShortByteString :: BS.ShortByteString }

b16 :: B16ShortByteString -> B.ByteString
b16 (B16ShortByteString b) = BS.fromShort b

instance Show B16ShortByteString where
    show (B16ShortByteString b) = concatMap (printf "%0.2x") $ BS.unpack b

-- This is rather inefficient. It is intended for string literals, debugging,
-- and testing.
--
instance IsString B16ShortByteString where
    fromString l
        | odd (length l) =
            error "Data.Hash.Internal.Utils.B16ShortByteString.fromString: odd input length"
        | otherwise = B16ShortByteString $ BS.pack $ go l
      where
        go [] = mempty
        go [_] = error "Data.Hash.Internal.Utils.B16ShortByteString.fromString: odd input length"
        go (a:b:t) = fromIntegral (shiftL (digitToInt a) 4 + digitToInt b) : go t

