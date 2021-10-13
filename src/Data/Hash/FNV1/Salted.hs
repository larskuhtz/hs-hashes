{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- |
-- Module: Data.Hash.FNV1.Salted
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Salted variants for FNV1 Hashes
--
module Data.Hash.FNV1.Salted
(
-- * Fnv1 64 bit
  FH.Fnv164Hash(..)
, FH.Fnv164Context


-- * Fnv1a 64 bit
, FH.Fnv1a64Hash(..)
, FH.Fnv1a64Context

-- * Fnv1 32 bit
, FH.Fnv132Hash(..)
, FH.Fnv132Context

-- * Fnv1a 32 bit
, FH.Fnv1a32Hash(..)
, FH.Fnv1a32Context

-- * Fnv1 Host Wordsize
, FH.Fnv1Hash(..)
, FH.Fnv1Context

-- * Fnv1a Host Wordsize
, FH.Fnv1aHash(..)
, FH.Fnv1aContext

-- * Utils
, module Data.Hash.Class.Pure.Salted

) where

import Data.Word

-- internal modules

import qualified Data.Hash.FNV1 as FH
import qualified Data.Hash.Class.Pure as PH
import Data.Hash.Class.Pure.Salted

-- -------------------------------------------------------------------------- --
-- Orphans

instance Hash FH.Fnv164Hash where
    type Salt FH.Fnv164Hash = Word64
    initialize = PH.initializeWithSalt @FH.Fnv164Hash
    {-# INLINE initialize #-}

instance Hash FH.Fnv1a64Hash where
    type Salt FH.Fnv1a64Hash = Word64
    initialize = PH.initializeWithSalt @FH.Fnv1a64Hash
    {-# INLINE initialize #-}

instance Hash FH.Fnv132Hash where
    type Salt FH.Fnv132Hash = Word32
    initialize = PH.initializeWithSalt @FH.Fnv132Hash
    {-# INLINE initialize #-}

instance Hash FH.Fnv1a32Hash where
    type Salt FH.Fnv1a32Hash = Word32
    initialize = PH.initializeWithSalt @FH.Fnv1a32Hash
    {-# INLINE initialize #-}

instance Hash FH.Fnv1Hash where
    type Salt FH.Fnv1Hash = Word
    initialize = PH.initializeWithSalt @FH.Fnv1Hash
    {-# INLINE initialize #-}

instance Hash FH.Fnv1aHash where
    type Salt FH.Fnv1aHash = Word
    initialize = PH.initializeWithSalt @FH.Fnv1aHash
    {-# INLINE initialize #-}

