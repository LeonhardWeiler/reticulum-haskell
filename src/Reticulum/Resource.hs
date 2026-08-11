{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Reticulum.Resource
    ( Advertisement (..)
    , advertisement
    , packAdvertisement
    , PartRequest (..)
    , partRequest
    , Update (..)
    , update
    , packUpdate
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
    , Giving (..)
    , giving
    , advertised
    , handing
    , concluded
    , hashLength
    , mapHashLength
    , randomHashLength
    , proofLength
    ) where

import Data.Bits (testBit, (.|.))
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

-- | The keys are written in the order the reference writes them, and a
-- field it has nothing for is nil and not left out.
packAdvertisement :: Advertisement -> ByteString
packAdvertisement value =
    Msgpack.pack
        ( Msgpack.Map
            [ (Msgpack.Text "t", number (transferSize value))
            , (Msgpack.Text "d", number (dataSize value))
            , (Msgpack.Text "n", number (parts value))
            , (Msgpack.Text "h", binary (resourceHash value))
            , (Msgpack.Text "r", binary (randomHash value))
            , (Msgpack.Text "o", binary (originalHash value))
            , (Msgpack.Text "i", number (segmentIndex value))
            , (Msgpack.Text "l", number (totalSegments value))
            , (Msgpack.Text "q", binary (requestId value))
            , (Msgpack.Text "f", number (fromIntegral <$> flags value))
            , (Msgpack.Text "m", binary (hashmap value))
            ]
        )
  where
    number = maybe Msgpack.Nil Msgpack.Unsigned
    binary = maybe Msgpack.Nil Msgpack.Bytes

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

packUpdate :: Update -> ByteString
packUpdate value =
    updatedResource value
        <> Msgpack.pack
            ( Msgpack.Array
                [ maybe Msgpack.Nil Msgpack.Unsigned (updateSegment value)
                , maybe Msgpack.Nil Msgpack.Bytes (updateHashmap value)
                ]
            )

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
    , replied :: Bool
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
taking size told = do
    hash <- resourceHash told
    entropy' <- randomHash told
    carried <- transferSize told
    flagged' <- flags told
    Just
        Taking
            { resource = hash
            , original = fromMaybe hash (originalHash told)
            , entropy = entropy'
            , index = fromMaybe 1 (segmentIndex told)
            , segments = fromMaybe 1 (totalSegments told)
            , identifier = requestId told
            , asked = testBit flagged' 3
            , replied = testBit flagged' 4
            , compressed = testBit flagged' 1
            , covered = testBit flagged' 0
            , prefixed = testBit flagged' 5
            , hashes = mapped (fromMaybe B.empty (hashmap told))
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
    carried = mark (entropy value) raw
    reached = length (takeWhile (`Map.member` gathered value) [0 ..])
    places = take window [reached .. pieces value - 1]

mark :: ByteString -> ByteString -> ByteString
mark salt' raw = B.take mapHashLength (Identity.fullHash (raw <> salt'))

extend :: Update -> Taking -> Taking
extend told value = case updateHashmap told of
    Nothing -> value
    Just more ->
        value
            { hashes = Map.union (hashes value) (Map.mapKeys (+ from) (mapped more))
            }
  where
    from = maybe 0 ((* hashmapSegment) . fromIntegral) (updateSegment told)

-- | An advertisement carries as many hashes as fit beside its own
-- fields, and every update after it carries that many again.
hashmapSegment :: Int
hashmapSegment = 74

whole :: Taking -> Maybe ByteString
whole value
    | Map.size (gathered value) == pieces value = Just (B.concat (Map.elems (gathered value)))
    | otherwise = Nothing

proving :: ByteString -> Taking -> ByteString
proving assembled value =
    resource value <> Identity.fullHash (assembled <> resource value)

-- | A resource being handed over: the sealed stream cut into parts, the
-- hash each part is known by, and the proof that ends it.
data Giving = Giving
    { given :: ByteString
    , salt :: ByteString
    , cut :: [ByteString]
    , marks :: [ByteString]
    , awaited :: ByteString
    , measure :: Int
    , squeezed :: Bool
    , answers :: Maybe (ByteString, Bool)
    , least :: Int
    }

-- | Both hashes are over the data, and neither is over what is sent:
-- the stream that goes out is compressed and sealed, and the far end
-- proves what it got back out of it.
giving :: Int -> ByteString -> ByteString -> ByteString -> Bool -> Maybe (ByteString, Bool) -> Giving
giving size salt' body stream compressed' asking =
    Giving
        { given = hash
        , salt = salt'
        , cut = chunks size stream
        , marks = map (mark salt') (chunks size stream)
        , awaited = Identity.fullHash (body <> hash)
        , measure = B.length body
        , squeezed = compressed'
        , answers = asking
        , least = 0
        }
  where
    hash = Identity.fullHash (body <> salt')

chunks :: Int -> ByteString -> [ByteString]
chunks size bytes
    | B.null bytes = []
    | otherwise = B.take size bytes : chunks size (B.drop size bytes)

advertised :: Giving -> Advertisement
advertised value =
    Advertisement
        { transferSize = Just (fromIntegral (sum (map B.length (cut value))))
        , dataSize = Just (fromIntegral (measure value))
        , parts = Just (fromIntegral (length (cut value)))
        , resourceHash = Just (given value)
        , randomHash = Just (salt value)
        , originalHash = Just (given value)
        , segmentIndex = Just 1
        , totalSegments = Just 1
        , requestId = fst <$> answers value
        , flags = Just (flagged value)
        , hashmap = Just (B.concat (take hashmapSegment (marks value)))
        }

-- | The stream is always sealed and never split, and the two bits that
-- say which way a request is going are the same bit read twice.
flagged :: Giving -> Word8
flagged value =
    1
        .|. (if squeezed value then 2 else 0)
        .|. (case answers value of Just (_, False) -> 8; _ -> 0)
        .|. (case answers value of Just (_, True) -> 16; _ -> 0)

-- | The window of parts a request can name is bounded, so a hash named
-- outside it is one this end no longer holds.
collisionGuard :: Int
collisionGuard = 2 * windowMax + hashmapSegment

windowMax :: Int
windowMax = 75

-- | What a part request asks for, and the next segment of the hashmap
-- when the far end says it has run out of the one it has.
handing :: PartRequest -> Giving -> ([ByteString], Maybe Update, Giving)
handing wanted value
    | exhausted wanted = (sending, Just told, value {least = max (reached - 1 - windowMax) 0})
    | otherwise = (sending, Nothing, value)
  where
    scope = take collisionGuard (drop (least value) (zip (marks value) (cut value)))
    named = chunks mapHashLength (requestedHashes wanted)
    sending = [piece | (hash, piece) <- scope, hash `elem` named]
    reached =
        least value
            + case break ((== lastMapHash wanted) . Just . fst) scope of
                (before, []) -> length before
                (before, _) -> length before + 1
    segment = reached `div` hashmapSegment
    told =
        Update
            { updatedResource = given value
            , updateSegment = Just (fromIntegral segment)
            , updateHashmap =
                Just
                    ( B.concat
                        (take hashmapSegment (drop (segment * hashmapSegment) (marks value)))
                    )
            }

concluded :: Proof -> Giving -> Bool
concluded written value =
    provedResource written == given value && dataHash written == awaited value
