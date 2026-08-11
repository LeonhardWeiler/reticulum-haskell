{-# LANGUAGE StrictData #-}

-- | RNS/Identity.py
module Reticulum.Identity
    ( PublicKey
    , publicKey
    , publicKeyBytes
    , x25519Public
    , ed25519Public
    , IdentityHash (..)
    , identityHash
    , fullHash
    , truncatedHash
    , keySize
    , truncatedHashLength
    ) where

import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as ByteArray
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

-- | RNS/Identity.py#KEYSIZE, in bytes.
keySize :: Int
keySize = 512 `div` 8

-- | RNS/Reticulum.py#TRUNCATED_HASHLENGTH, in bytes.
truncatedHashLength :: Int
truncatedHashLength = 128 `div` 8

-- | RNS/Identity.py#full_hash
fullHash :: ByteString -> ByteString
fullHash = ByteArray.convert . sha256
  where
    sha256 :: ByteString -> Hash.Digest Hash.SHA256
    sha256 = Hash.hash

-- | RNS/Identity.py#truncated_hash
truncatedHash :: ByteString -> ByteString
truncatedHash = B.take truncatedHashLength . fullHash

-- | RNS/Identity.py#pub_bytes: the X25519 half then the Ed25519 half.
newtype PublicKey = PublicKey {publicKeyBytes :: ByteString}

-- | RNS/Identity.py#update_hashes
newtype IdentityHash = IdentityHash {identityHashBytes :: ByteString}

publicKey :: ByteString -> Either String PublicKey
publicKey bytes
    | B.length bytes == keySize = Right (PublicKey bytes)
    | otherwise =
        Left $
            "public key is "
                ++ show (B.length bytes)
                ++ " bytes, not "
                ++ show keySize

x25519Public :: PublicKey -> ByteString
x25519Public = B.take (keySize `div` 2) . publicKeyBytes

ed25519Public :: PublicKey -> ByteString
ed25519Public = B.drop (keySize `div` 2) . publicKeyBytes

identityHash :: PublicKey -> IdentityHash
identityHash = IdentityHash . truncatedHash . publicKeyBytes
