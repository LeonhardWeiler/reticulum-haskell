{-# LANGUAGE StrictData #-}

module Reticulum.Token
    ( Token (..)
    , token
    , pack
    , Keys (..)
    , keys
    , hmacValid
    , open
    , seal
    , tokenOverhead
    , blockSize
    ) where

import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (cbcDecrypt, cbcEncrypt, cipherInit, makeIV)
import Crypto.Error (CryptoFailable, maybeCryptoError)
import qualified Crypto.Hash as Hash
import qualified Crypto.MAC.HMAC as HMAC
import qualified Data.ByteArray as ByteArray
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Reticulum.Packet (Rejection (ShortPayload))

ivLength :: Int
ivLength = 16

hmacLength :: Int
hmacLength = 32

blockSize :: Int
blockSize = 16

tokenOverhead :: Int
tokenOverhead = ivLength + hmacLength

data Token = Token
    { iv :: ByteString
    , ciphertext :: ByteString
    , hmac :: ByteString
    }

data Keys = Keys
    { signingKey :: ByteString
    , encryptionKey :: ByteString
    }

token :: ByteString -> Either Rejection Token
token payload
    | length' < tokenOverhead = Left (ShortPayload length' tokenOverhead)
    | otherwise =
        Right
            Token
                { iv = B.take ivLength payload
                , ciphertext = B.take (length' - tokenOverhead) (B.drop ivLength payload)
                , hmac = B.drop (length' - hmacLength) payload
                }
  where
    length' = B.length payload

pack :: Token -> ByteString
pack value = B.concat [iv value, ciphertext value, hmac value]

keys :: ByteString -> Keys
keys derived = Keys (B.take half derived) (B.drop half derived)
  where
    half = B.length derived `div` 2

-- | The ephemeral public key travels beside the token and is not covered.
hmacValid :: Keys -> Token -> Bool
hmacValid key value =
    ByteArray.constEq (hmac value) (mac (signingKey key) (iv value <> ciphertext value))

mac :: ByteString -> ByteString -> ByteString
mac key message = ByteArray.convert (HMAC.hmac key message :: HMAC.HMAC Hash.SHA256)

open :: Keys -> Token -> Maybe ByteString
open key value
    | hmacValid key value = unpad =<< decrypt (encryptionKey key) (iv value) (ciphertext value)
    | otherwise = Nothing

seal :: Keys -> ByteString -> ByteString -> Maybe Token
seal key vector plain = do
    block <- encrypt (encryptionKey key) vector (pad plain)
    Just (Token vector block (mac (signingKey key) (vector <> block)))

encrypt :: ByteString -> ByteString -> ByteString -> Maybe ByteString
encrypt key vector block = do
    cipher <- maybeCryptoError (cipherInit key :: CryptoFailable AES256)
    start <- makeIV vector
    Just (cbcEncrypt cipher start block)

-- | A plaintext that already fills the last block is followed by a whole
-- block of padding.
pad :: ByteString -> ByteString
pad plain = plain <> B.replicate added (fromIntegral added)
  where
    added = blockSize - B.length plain `mod` blockSize

decrypt :: ByteString -> ByteString -> ByteString -> Maybe ByteString
decrypt key vector block
    | B.length block `mod` blockSize /= 0 = Nothing
    | otherwise = do
        cipher <- maybeCryptoError (cipherInit key :: CryptoFailable AES256)
        start <- makeIV vector
        Just (cbcDecrypt cipher start block)

-- | A length above the block size is the only rule: zero removes
-- nothing, and the padding bytes are never compared against it.
unpad :: ByteString -> Maybe ByteString
unpad plain = do
    (_, final) <- B.unsnoc plain
    let removed = fromIntegral final
    if removed > blockSize
        then Nothing
        else Just (B.take (B.length plain - removed) plain)
