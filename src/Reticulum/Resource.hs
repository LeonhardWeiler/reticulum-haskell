{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Reticulum.Resource
    ( Advertisement (..)
    , advertisement
    , PartRequest (..)
    , partRequest
    , Update (..)
    , update
    , cancel
    , Proof (..)
    , proof
    , packProof
    , hashLength
    , mapHashLength
    , proofLength
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word (Word64, Word8)

import qualified Reticulum.Msgpack as Msgpack
import Reticulum.Packet (Rejection (FixedLength, ShortPlaintext))

hashLength :: Int
hashLength = 32

mapHashLength :: Int
mapHashLength = 4

proofLength :: Int
proofLength = 2 * hashLength

-- | One value, not a byte tested for truth, and it decides where the
-- resource hash begins.
hashmapIsExhausted :: Word8
hashmapIsExhausted = 0xff

data Advertisement = Advertisement
    { transferSize :: Maybe Word64
    , dataSize :: Maybe Word64
    , parts :: Maybe Word64
    , resourceHash :: Maybe ByteString
    , randomHash :: Maybe ByteString
    , originalHash :: Maybe ByteString
    , segmentIndex :: Maybe Word64
    , totalSegments :: Maybe Word64
    , requestId :: Maybe ByteString
    , flags :: Maybe Word8
    , hashmap :: Maybe ByteString
    }

-- | A map is not a sequence, and a reader that goes by position agrees
-- with this reference and with nothing entitled to reorder the keys.
advertisement :: ByteString -> Either Rejection Advertisement
advertisement plain
    | B.null plain = Left (ShortPlaintext 1)
    | otherwise =
        Right
            Advertisement
                { transferSize = number "t"
                , dataSize = number "d"
                , parts = number "n"
                , resourceHash = binary "h"
                , randomHash = binary "r"
                , originalHash = binary "o"
                , segmentIndex = number "i"
                , totalSegments = number "l"
                , requestId = binary "q"
                , flags = fromIntegral <$> number "f"
                , hashmap = binary "m"
                }
  where
    packed = Msgpack.unpack plain
    held key = Msgpack.entry key =<< packed
    number key = case held key of
        Just (Msgpack.Unsigned count) -> Just count
        _ -> Nothing
    binary key = case held key of
        Just (Msgpack.Bytes bytes) -> Just bytes
        _ -> Nothing

data PartRequest = PartRequest
    { exhausted :: Bool
    , lastMapHash :: Maybe ByteString
    , requestedResource :: ByteString
    , requestedHashes :: ByteString
    }

partRequest :: ByteString -> Either Rejection PartRequest
partRequest plain = case B.uncons plain of
    Nothing -> Left (ShortPlaintext 1)
    Just (flag, _)
        | B.length plain < needed -> Left (ShortPlaintext needed)
        | otherwise ->
            Right
                PartRequest
                    { exhausted = gone
                    , lastMapHash =
                        if gone then Just (B.take mapHashLength (B.drop 1 plain)) else Nothing
                    , requestedResource = B.take hashLength (B.drop hashAt plain)
                    , requestedHashes = B.drop (hashAt + hashLength) plain
                    }
      where
        gone = flag == hashmapIsExhausted
        hashAt = 1 + (if gone then mapHashLength else 0)
        needed = hashAt + hashLength

data Update = Update
    { updatedResource :: ByteString
    , updateSegment :: Maybe Word64
    , updateHashmap :: Maybe ByteString
    }

-- | The hash is raw and what follows it is msgpack, which is the one
-- payload that is half of each.
update :: ByteString -> Either Rejection Update
update plain
    | B.length plain < needed = Left (ShortPlaintext needed)
    | otherwise =
        Right
            Update
                { updatedResource = B.take hashLength plain
                , updateSegment = case Msgpack.element 0 =<< packed of
                    Just (Msgpack.Unsigned count) -> Just count
                    _ -> Nothing
                , updateHashmap = case Msgpack.element 1 =<< packed of
                    Just (Msgpack.Bytes bytes) -> Just bytes
                    _ -> Nothing
                }
  where
    needed = hashLength + 1
    packed = Msgpack.unpack (B.drop hashLength plain)

cancel :: ByteString -> ByteString
cancel = B.take hashLength

-- | Neither half is what the same two lengths mean in a delivery proof:
-- nothing here is signed.
data Proof = Proof
    { provedResource :: ByteString
    , dataHash :: ByteString
    }

proof :: ByteString -> Either Rejection Proof
proof payload
    | B.length payload == proofLength =
        Right (Proof (B.take hashLength payload) (B.drop hashLength payload))
    | otherwise = Left (FixedLength (B.length payload) proofLength)

packProof :: Proof -> ByteString
packProof value = provedResource value <> dataHash value
