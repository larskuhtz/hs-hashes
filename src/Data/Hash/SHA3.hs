{-# LANGUAGE ExplicitNamespaces #-}

-- |
-- Module: Data.Hash.SHA3
-- Copyright: Copyright © 2021-2024 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- SHA-3 Hash Functions
--
module Data.Hash.SHA3
(
-- * SHA-3
--
-- | SHA-3 (Secure Hash Algorithm 3) is a family of cryptographic hash functions
-- standardized in NIST FIPS 202, first published in 2015. It is based on the
-- Keccak algorithm. These functions conform to NIST FIPS 202.

  Sha3_224(..)
, Sha3_256(..)
, Sha3_384(..)
, Sha3_512(..)
, Shake128(..)
, type Shake128_256
, Shake256(..)
, type Shake256_512

, module Data.Hash.Class.Mutable
) where

import Data.Hash.Class.Mutable
import Data.Hash.Internal.OpenSSL

