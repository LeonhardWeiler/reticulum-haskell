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
    , sign
    , validate
    , keySize
    , signatureLength
    , ratchetSize
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

-- | RNS/Identity.py#SIGLENGTH, in bytes.
signatureLength :: Int
signatureLength = 512 `div` 8

-- | RNS/Identity.py#RATCHETSIZE, in bytes.
ratchetSize :: Int
ratchetSize = 256 `div` 8

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

-- | RNS/Identity.py#sign. Ed25519 signing is deterministic, RFC 8032
-- section 5.1.6: the nonce comes from the key and the message and not
-- from a random source, so the answer is a single value. The Ed25519
-- half signs; the X25519 half is not a signing key.
sign :: PrivateKey -> ByteString -> Either String ByteString
sign key message = case Ed25519.secretKey (ed25519Private key) of
    CryptoFailed reason -> Left ("ed25519 private key: " ++ show reason)
    CryptoPassed secret ->
        Right (ByteArray.convert (Ed25519.sign secret (Ed25519.toPublic secret) message))

-- | RNS/Identity.py#validate. Ed25519 over the message as it stands:
-- no prefix, no domain separator, no prior hashing.
validate :: PublicKey -> ByteString -> ByteString -> Bool
validate key message signature =
    case (Ed25519.publicKey (ed25519Public key), Ed25519.signature signature) of
        (CryptoPassed verifier, CryptoPassed signed)
            | canonicalS signature -> Ed25519.verify verifier message signed
        _ -> False

-- | RFC 8032 section 5.1.7 admits only S < L, and S + L is a second
-- encoding of the same signature. python-rns picks its curve at import
-- time and the two disagree here: the openssl backend in the pin
-- rejects S + L, the internal fallback accepts it. A signer never
-- produces one, so this is a receiving-side rule, and a verifier that
-- reduces S instead of checking it interoperates in one direction.
--
-- RNS/Cryptography/Provider.py#PROVIDER_PYCA
canonicalS :: ByteString -> Bool
canonicalS signature =
    B.length s == B.length groupOrder && B.reverse s < groupOrder
  where
    s = B.drop (signatureLength `div` 2) signature

-- | L, big endian. RFC 8032 section 5.1: 2^252 + 27742317777372353535851937790883648493.
groupOrder :: ByteString
groupOrder =
    B.pack
        [ 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        , 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6
        , 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
        ]
