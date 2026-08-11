{-# LANGUAGE StrictData #-}

module Reticulum.Encryption
    ( Encrypted (..)
    , encrypted
    , pack
    , sealed
    , opened
    , shared
    , derive
    , publicPoint
    , ephemeralLength
    , derivedKeyLength
    ) where

import qualified Crypto.Hash as Hash
import qualified Crypto.KDF.HKDF as HKDF
import qualified Crypto.PubKey.Curve25519 as X25519
import Crypto.Error (maybeCryptoError)
import qualified Data.ByteArray as ByteArray
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Reticulum.Packet (Rejection (ShortPayload))
import Reticulum.Token (Token)
import qualified Reticulum.Token as Token

ephemeralLength :: Int
ephemeralLength = 32

derivedKeyLength :: Int
derivedKeyLength = 64

data Encrypted = Encrypted
    { ephemeralPublic :: ByteString
    , token :: Token
    }

encrypted :: ByteString -> Either Rejection Encrypted
encrypted payload
    | B.length payload < needed = Left (ShortPayload (B.length payload) needed)
    | otherwise =
        Encrypted (B.take ephemeralLength payload)
            <$> Token.token (B.drop ephemeralLength payload)
  where
    needed = ephemeralLength + Token.tokenOverhead

pack :: Encrypted -> ByteString
pack value = ephemeralPublic value <> Token.pack (token value)

-- | The salt is the hash of the identity the plaintext is for, and the
-- ephemeral point travels in front of the token.
sealed
    :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString -> Maybe Encrypted
sealed ephemeral peer salt vector plain = do
    point <- publicPoint ephemeral
    agreed <- shared ephemeral peer
    Encrypted point <$> Token.seal (agreedKeys agreed salt) vector plain

opened :: ByteString -> ByteString -> Encrypted -> Maybe ByteString
opened scalar salt value = do
    agreed <- shared scalar (ephemeralPublic value)
    Token.open (agreedKeys agreed salt) (token value)

agreedKeys :: ByteString -> ByteString -> Token.Keys
agreedKeys agreed salt = Token.keys (derive derivedKeyLength agreed salt)

-- | An agreement against a point of small order is all zeroes, which
-- neither end contributed to and every reader of the announce can
-- compute.
shared :: ByteString -> ByteString -> Maybe ByteString
shared scalar peer = do
    secret <- maybeCryptoError (X25519.secretKey scalar)
    point <- maybeCryptoError (X25519.publicKey peer)
    let agreed = ByteArray.convert (X25519.dh point secret)
    if B.all (== 0) agreed then Nothing else Just agreed

derive :: Int -> ByteString -> ByteString -> ByteString
derive length' secret salt = HKDF.expand prk B.empty length'
  where
    prk = HKDF.extract salt secret :: HKDF.PRK Hash.SHA256

publicPoint :: ByteString -> Maybe ByteString
publicPoint scalar =
    ByteArray.convert . X25519.toPublic <$> maybeCryptoError (X25519.secretKey scalar)
