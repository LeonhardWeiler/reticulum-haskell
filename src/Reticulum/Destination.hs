{-# LANGUAGE StrictData #-}

-- | RNS/Destination.py
module Reticulum.Destination
    ( Name (nameBytes, appName, aspects)
    , name
    , fromComponents
    , NameHash (..)
    , nameHash
    , DestinationHash (..)
    , destinationHash
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word (Word8)

import Reticulum.Identity (IdentityHash (identityHashBytes))
import qualified Reticulum.Identity as Identity

-- | An app name followed by zero or more aspects, joined with a single
-- dot. A component may be empty; nothing forbids it.
--
-- RNS/Destination.py#app_and_aspects_from_name
data Name = Name
    { nameBytes :: ByteString
    , appName :: ByteString
    , aspects :: [ByteString]
    }

dot :: Word8
dot = 0x2e

name :: ByteString -> Name
name bytes = case B.split dot bytes of
    -- An empty name splits into no components here and into one empty
    -- one in Python, where the app name is that empty component.
    [] -> Name bytes B.empty []
    (app : rest) -> Name bytes app rest

-- | RNS/Destination.py#expand_name, with the identity left out: the
-- path that appends it produces the human-readable name only and is
-- not the one the hashes are derived through.
fromComponents :: ByteString -> [ByteString] -> Either String Name
fromComponents app parts
    | any (B.elem dot) components = Left "dots can't be used in app names or aspects"
    | otherwise = Right (Name (B.intercalate (B.singleton dot) components) app parts)
  where
    components = app : parts

newtype NameHash = NameHash {nameHashBytes :: ByteString}

newtype DestinationHash = DestinationHash {destinationHashBytes :: ByteString}

-- | RNS/Destination.py#hash. The name is hashed as its utf-8 bytes
-- exactly as given: no unicode normalisation, so a precomposed name
-- and its decomposed form are two destinations.
nameHash :: Name -> NameHash
nameHash = NameHash . B.take Identity.nameHashLength . Identity.fullHash . nameBytes

-- | RNS/Destination.py#hash. The identity is mixed in here, after the
-- name has been hashed, and not as part of the name. Without one the
-- material is the name hash alone.
destinationHash :: NameHash -> Maybe IdentityHash -> DestinationHash
destinationHash hash identity =
    DestinationHash (Identity.truncatedHash (nameHashBytes hash <> material))
  where
    material = maybe B.empty identityHashBytes identity
