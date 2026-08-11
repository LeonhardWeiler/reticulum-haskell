{-# LANGUAGE StrictData #-}

module Reticulum.Link
    ( Request (..)
    , request
    , mode
    , mtu
    , linkId
    , publicKeysLength
    , signallingSize
    , modeAes256Cbc
    ) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word (Word8)

import qualified Reticulum.Identity as Identity
import Reticulum.Packet (Rejection (SignalledLength))
import qualified Reticulum.Packet as Packet

publicKeysLength :: Int
publicKeysLength = 64

signallingSize :: Int
signallingSize = 3

modeAes256Cbc :: Word8
modeAes256Cbc = 0x01

mtuBytemask :: Int
mtuBytemask = 0x1fffff

modeBytemask :: Word8
modeBytemask = 0xe0

data Request = Request
    { x25519Public :: ByteString
    , ed25519Public :: ByteString
    , signalling :: Maybe ByteString
    }

request :: ByteString -> Either Rejection Request
request payload
    | length' == publicKeysLength = Right (keys Nothing)
    | length' == publicKeysLength + signallingSize =
        Right (keys (Just (B.drop publicKeysLength payload)))
    | otherwise =
        Left (SignalledLength length' publicKeysLength (publicKeysLength + signallingSize))
  where
    length' = B.length payload
    half = publicKeysLength `div` 2
    keys = Request (B.take half payload) (B.take half (B.drop half payload))

-- | The decoder returns the three bits it read whatever they are, and
-- an unsignalled request reads as the one mode the reference enables.
mode :: Request -> Word8
mode value = case B.uncons =<< signalling value of
    Just (byte, _) -> (byte .&. modeBytemask) `shiftR` 5
    Nothing -> modeAes256Cbc

mtu :: Request -> Maybe Int
mtu value = (.&. mtuBytemask) . bigEndian <$> signalling value

bigEndian :: ByteString -> Int
bigEndian = B.foldl' (\value byte -> (value `shiftL` 8) .|. fromIntegral byte) 0

-- | The signalling bytes are cut off the end, so a request that signals
-- an MTU opens the link a request without one opens.
linkId :: Packet.Packet -> ByteString
linkId unpacked = Identity.truncatedHash (B.take (B.length part - signalled) part)
  where
    part = Packet.hashablePart unpacked
    signalled = max 0 (B.length (Packet.payload unpacked) - publicKeysLength)
