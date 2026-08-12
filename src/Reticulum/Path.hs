{-# LANGUAGE StrictData #-}

module Reticulum.Path
    ( Time (..)
    , Heard (..)
    , Path (..)
    , Table
    , learn
    , shorten
    , expired
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)

import Reticulum.Destination (DestinationHash)

newtype Time = Time {seconds :: Double}
    deriving (Eq, Ord)

lifetime :: Double
lifetime = 60 * 60 * 24 * 7

maximumBlobs :: Int
maximumBlobs = 64

-- | An announce as the table takes it: where it came from and the ten
-- bytes that say which announce it is.
data Heard i = Heard
    { sender :: ByteString
    , travelled :: Word8
    , blob :: ByteString
    , announceHash :: ByteString
    , through :: i
    }

data Path i = Path
    { via :: ByteString
    , hops :: Word8
    , updated :: Time
    , expires :: Time
    , blobs :: [ByteString]
    , announced :: ByteString
    , interface :: i
    }

type Table i = Map DestinationHash (Path i)

-- | Nothing where the table keeps what it had, and an announce the
-- table keeps nothing of is one nothing above it hears about.
learn :: Time -> DestinationHash -> Heard i -> Table i -> Maybe (Path i, Table i)
learn now destination heard table = case Map.lookup destination table of
    Nothing -> Just (taken [])
    Just old
        | replaces now heard old -> Just (taken (blobs old))
        | otherwise -> Nothing
  where
    taken kept = (entry kept, Map.insert destination (entry kept) table)
    entry kept =
        Path
            { via = sender heard
            , hops = travelled heard
            , updated = now
            , expires = Time (seconds now + lifetime)
            , blobs = remembered kept (blob heard)
            , announced = announceHash heard
            , interface = through heard
            }

-- | An announce already heard is a loop, and the shorter path wins only
-- when it was emitted after the one on file.
replaces :: Time -> Heard i -> Path i -> Bool
replaces now heard old
    | travelled heard <= hops old = unheard && emitted > timebaseOf (blobs old)
    | expires old <= now = unheard
    | otherwise = emitted > reached && unheard
  where
    unheard = blob heard `notElem` blobs old
    emitted = timebase (blob heard)
    reached = timebaseUpTo emitted (blobs old)

-- | Five random bytes, then five of the unix time the announce was
-- emitted at.
timebase :: ByteString -> Word64
timebase = B.foldl' step 0 . B.take 5 . B.drop 5
  where
    step accumulated byte = accumulated * 256 + fromIntegral byte

timebaseOf :: [ByteString] -> Word64
timebaseOf = foldr (max . timebase) 0

-- | The scan stops at the first blob that reaches the announce, so a
-- later and higher emission behind it does not count against it.
timebaseUpTo :: Word64 -> [ByteString] -> Word64
timebaseUpTo target = go 0
  where
    go seen [] = seen
    go seen (held : rest)
        | reached >= target = reached
        | otherwise = go reached rest
      where
        reached = max seen (timebase held)

remembered :: [ByteString] -> ByteString -> [ByteString]
remembered kept new
    | new `elem` kept = kept
    | otherwise = drop (length grown - maximumBlobs) grown
  where
    grown = kept ++ [new]

shorten :: Word8 -> DestinationHash -> Table i -> Table i
shorten away = Map.adjust (\path -> path {hops = away})

expired :: Time -> Path i -> Bool
expired now path = expires path <= now
