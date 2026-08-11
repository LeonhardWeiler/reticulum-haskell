{-# LANGUAGE StrictData #-}

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
    , verify
    , keySize
    , signatureLength
    , ratchetSize
    , hashLength
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

keySize :: Int
keySize = 64

signatureLength :: Int
signatureLength = 64

ratchetSize :: Int
ratchetSize = 32

hashLength :: Int
hashLength = 32

truncatedHashLength :: Int
truncatedHashLength = hashLength `div` 2

nameHashLength :: Int
nameHashLength = 10

fullHash :: ByteString -> ByteString
fullHash = ByteArray.convert . sha256
  where
    sha256 :: ByteString -> Hash.Digest Hash.SHA256
    sha256 = Hash.hash

truncatedHash :: ByteString -> ByteString
truncatedHash = B.take truncatedHashLength . fullHash

newtype PublicKey = PublicKey {publicKeyBytes :: ByteString}

-- | The X25519 scalar is held exactly as supplied, and clamping happens
-- inside the curve when it is used.
newtype PrivateKey = PrivateKey {privateKeyBytes :: ByteString}

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

sign :: PrivateKey -> ByteString -> Either String ByteString
sign key message = case Ed25519.secretKey (ed25519Private key) of
    CryptoFailed reason -> Left ("ed25519 private key: " ++ show reason)
    CryptoPassed secret ->
        Right (ByteArray.convert (Ed25519.sign secret (Ed25519.toPublic secret) message))

validate :: PublicKey -> ByteString -> ByteString -> Bool
validate = verify . ed25519Public

verify :: ByteString -> ByteString -> ByteString -> Bool
verify key message signature =
    case (Ed25519.publicKey key, Ed25519.signature signature) of
        (CryptoPassed verifier, CryptoPassed signed)
            | canonicalS signature -> Ed25519.verify verifier message signed
        _ -> False

-- | Only S below the group order is a signature, and crypton reduces S
-- rather than refusing S + L.
canonicalS :: ByteString -> Bool
canonicalS signature =
    B.length s == B.length groupOrder && B.reverse s < groupOrder
  where
    s = B.drop (signatureLength `div` 2) signature

groupOrder :: ByteString
groupOrder =
    B.pack
        [ 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        , 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6
        , 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
        ]
