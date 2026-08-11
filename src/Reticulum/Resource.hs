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
    , Taking (..)
    , taking
    , next
    , part
    , extend
    , whole
    , proving
    , hashLength
    , mapHashLength
    , randomHashLength
    , proofLength
    ) where

import Data.Bits (testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Word (Word64, Word8)

import qualified Reticulum.Identity as Identity
import qualified Reticulum.Msgpack as Msgpack
import Reticulum.Packet (Rejection (FixedLength, ShortPlaintext))

hashLength :: Int
hashLength = 32

mapHashLength :: Int
mapHashLength = 4

randomHashLength :: Int
randomHashLength = 4

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

-- | A resource being taken in: the hashes it was told to ask for, the
-- parts that answered them, and how many are still outstanding.
data Taking = Taking
    { resource :: ByteString
    , original :: ByteString
    , entropy :: ByteString
    , index :: Word64
    , segments :: Word64
    , identifier :: Maybe ByteString
    , asked :: Bool
    , compressed :: Bool
    , covered :: Bool
    , prefixed :: Bool
    , hashes :: Map Int ByteString
    , gathered :: Map Int ByteString
    , pieces :: Int
    , outstanding :: Int
    }

window :: Int
window = 4

-- | The parts are as many as the transfer size divided by what one of
-- them carries, and an advertisement that names neither is none.
taking :: Int -> Advertisement -> Maybe Taking
taking size advertised = do
    hash <- resourceHash advertised
    salt <- randomHash advertised
    carried <- transferSize advertised
    flagged <- flags advertised
    Just
        Taking
            { resource = hash
            , original = fromMaybe hash (originalHash advertised)
            , entropy = salt
            , index = fromMaybe 1 (segmentIndex advertised)
            , segments = fromMaybe 1 (totalSegments advertised)
            , identifier = requestId advertised
            , asked = testBit flagged 3
            , compressed = testBit flagged 1
            , covered = testBit flagged 0
            , prefixed = testBit flagged 5
            , hashes = mapped (fromMaybe B.empty (hashmap advertised))
            , gathered = Map.empty
            , pieces = ceiling (fromIntegral carried / fromIntegral size :: Double)
            , outstanding = 0
            }

mapped :: ByteString -> Map Int ByteString
mapped bytes =
    Map.fromList
        [ (place, B.take mapHashLength (B.drop (place * mapHashLength) bytes))
        | place <- [0 .. B.length bytes `div` mapHashLength - 1]
        ]

-- | The hashes asked for are the window's worth from the first part
-- missing, and running out of them is the one thing the first byte says.
next :: Taking -> Maybe (ByteString, Taking)
next value
    | Map.size (gathered value) >= pieces value = Nothing
    | otherwise = Just (asking, value {outstanding = length wanted})
  where
    reached = length (takeWhile (`Map.member` gathered value) [0 ..])
    places = take window [reached .. pieces value - 1]
    missing = filter (`Map.notMember` gathered value) places
    wanted = [hash | place <- missing, Just hash <- [Map.lookup place (hashes value)]]
    ranOut = length wanted < length missing
    asking =
        B.concat
            [ if ranOut
                then B.singleton hashmapIsExhausted <> lastKnown
                else B.singleton 0x00
            , resource value
            , B.concat wanted
            ]
    lastKnown = maybe B.empty snd (Map.lookupMax (hashes value))

-- | A part is known by the hash of itself and the resource's random
-- hash, and only inside the window it was asked in.
part :: ByteString -> Taking -> Taking
part raw value = case [place | place <- places, Map.lookup place (hashes value) == Just carried] of
    (place : _)
        | place `Map.notMember` gathered value ->
            value
                { gathered = Map.insert place raw (gathered value)
                , outstanding = max 0 (outstanding value - 1)
                }
    _ -> value
  where
    carried = B.take mapHashLength (Identity.fullHash (raw <> entropy value))
    reached = length (takeWhile (`Map.member` gathered value) [0 ..])
    places = take window [reached .. pieces value - 1]

extend :: Update -> Taking -> Taking
extend told value = case updateHashmap told of
    Nothing -> value
    Just more ->
        value
            { hashes = Map.union (hashes value) (Map.mapKeys (+ from) (mapped more))
            }
  where
    from = maybe 0 (fromIntegral . (* hashmapSegment)) (updateSegment told)

-- | An advertisement carries as many hashes as fit beside its own
-- fields, and every update after it carries that many again.
hashmapSegment :: Word64
hashmapSegment = 74

whole :: Taking -> Maybe ByteString
whole value
    | Map.size (gathered value) == pieces value = Just (B.concat (Map.elems (gathered value)))
    | otherwise = Nothing

proving :: ByteString -> Taking -> ByteString
proving assembled value =
    resource value <> Identity.fullHash (assembled <> resource value)
