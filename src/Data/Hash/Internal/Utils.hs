{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: Data.Hash.Internal.Utils
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
module Data.Hash.Internal.Utils
( B16ShortByteString(..)
) where

import qualified Data.ByteString.Short as BS

import Text.Printf

-- -------------------------------------------------------------------------- --
-- Utils

newtype B16ShortByteString = B16ShortByteString BS.ShortByteString

instance Show B16ShortByteString where
    show (B16ShortByteString b) = concatMap (printf "%0.2x") $ BS.unpack b

