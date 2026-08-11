{-# LANGUAGE StrictData #-}

-- | RNS/Identity.py
module Reticulum.Identity
    ( PublicKey
    , publicKey
    , publicKeyBytes
    , x25519Public
    , ed25519Public
    , PrivateKey
    , privateKey
    , privateKeyBytes
    , x25519Private
    , ed25519Private
    , toPublic
    , IdentityHash (..)
    , identityHash
    , fullHash
    , truncatedHash
    , keySize
    , truncatedHashLength
    , nameHashLength
    ) where

import Crypto.Error (CryptoFailable (CryptoFailed, CryptoPassed))
import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ByteArray as ByteArray
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

-- | RNS/Identity.py#KEYSIZE, in bytes.
keySize :: Int
keySize = 512 `div` 8

-- | RNS/Reticulum.py#TRUNCATED_HASHLENGTH, in bytes.
truncatedHashLength :: Int
truncatedHashLength = 128 `div` 8

-- | RNS/Identity.py#NAME_HASH_LENGTH, in bytes. Ten, not sixteen.
nameHashLength :: Int
nameHashLength = 80 `div` 8

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

-- | RNS/Identity.py#prv_bytes: an X25519 scalar then an Ed25519 seed.
-- The two halves are unrelated and neither is derived from the other.
-- The scalar is held exactly as supplied; clamping happens inside the
-- curve when it is used, so a key exported here is the key imported.
newtype PrivateKey = PrivateKey {privateKeyBytes :: ByteString}

-- | RNS/Identity.py#update_hashes
newtype IdentityHash = IdentityHash {identityHashBytes :: ByteString}

publicKey :: ByteString -> Either String PublicKey
publicKey = fmap PublicKey . ofKeySize "public key"

privateKey :: ByteString -> Either String PrivateKey
privateKey = fmap PrivateKey . ofKeySize "private key"

ofKeySize :: String -> ByteString -> Either String ByteString
ofKeySize what bytes
    | B.length bytes == keySize = Right bytes
    | otherwise =
        Left $
            what
                ++ " is "
                ++ show (B.length bytes)
                ++ " bytes, not "
                ++ show keySize

halfSize :: Int
halfSize = keySize `div` 2

x25519Public :: PublicKey -> ByteString
x25519Public = B.take halfSize . publicKeyBytes

ed25519Public :: PublicKey -> ByteString
ed25519Public = B.drop halfSize . publicKeyBytes

x25519Private :: PrivateKey -> ByteString
x25519Private = B.take halfSize . privateKeyBytes

ed25519Private :: PrivateKey -> ByteString
ed25519Private = B.drop halfSize . privateKeyBytes

-- | RNS/Identity.py#load_private_key: each half is taken to its own
-- curve and the two public keys are concatenated in the same order.
toPublic :: PrivateKey -> Either String PublicKey
toPublic key = do
    x <- curve "x25519" X25519.secretKey (x25519Private key)
    ed <- curve "ed25519" Ed25519.secretKey (ed25519Private key)
    publicKey (ByteArray.convert (X25519.toPublic x) <> ByteArray.convert (Ed25519.toPublic ed))
  where
    curve what secret bytes = case secret bytes of
        CryptoFailed reason -> Left (what ++ " private key: " ++ show reason)
        CryptoPassed value -> Right value

identityHash :: PublicKey -> IdentityHash
identityHash = IdentityHash . truncatedHash . publicKeyBytes
