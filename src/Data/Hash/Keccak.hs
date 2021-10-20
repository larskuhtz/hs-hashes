{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Data.Hash.Keccak
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- | The code in this module uses internal OpenSSL APIs. It may break with new
-- versions of OpenSSL. It may also be broken for existing versions of OpenSSL.
-- Portability of the code is unknown.
--
-- ONLY USE THIS CODE AFTER YOU HAVE VERIFIED THAT IT WORKS WITH OUR VERSION OF
-- OPENSSL.
--
-- For details see the file cbits/keccak.c.
--
module Data.Hash.Keccak
(
-- * Keccak-256
--
-- | This is the latest version of Keccak-256 hash function that was submitted to
-- the SHA3 competition. It is different from the final NIST SHA3 hash.
--
-- The difference between NIST SHA3-256 and Keccak-256 is the use of a different
-- padding character for the input message. The former uses '0x06' and the
-- latter uses '0x01'.
--
-- This version of Keccak-256 is used by the Ethereum project.

  Keccak256(..)
, module Data.Hash.Class.Mutable
) where

import Data.Hash.Class.Mutable
import Data.Hash.Internal.OpenSSL

