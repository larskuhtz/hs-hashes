-- |
-- Module: Data.Hash.Blake2
-- Copyright: Copyright © 2021 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Blake2 Hash Functions
--
module Data.Hash.Blake2
(
-- * Blake2
--
-- | BLAKE2 is an improved version of BLAKE, which was submitted to the NIST SHA-3
-- algorithm competition. The BLAKE2s and BLAKE2b algorithms are described in
-- RFC 7693.
--
-- While the BLAKE2b and BLAKE2s algorithms supports a variable length digest,
-- this implementation outputs a digest of a fixed length (the maximum length
-- supported), which is 512-bits for BLAKE2b and 256-bits for BLAKE2s.

  Blake2b512(..)
, Blake2s256(..)

, module Data.Hash.Class.Mutable
) where

import Data.Hash.Class.Mutable
import Data.Hash.Internal.OpenSSL


