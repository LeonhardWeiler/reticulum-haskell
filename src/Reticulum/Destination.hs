{-# LANGUAGE StrictData #-}

module Reticulum.Destination
    ( Name (nameBytes, appName, aspects)
    , name
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

data Name = Name
    { nameBytes :: ByteString
    , appName :: ByteString
    , aspects :: [ByteString]
    }

dot :: Word8
dot = 0x2e

name :: ByteString -> Name
name bytes = case B.split dot bytes of
    -- An empty name has an empty app name and no aspects.
    [] -> Name bytes B.empty []
    (app : rest) -> Name bytes app rest

newtype NameHash = NameHash {nameHashBytes :: ByteString}

newtype DestinationHash = DestinationHash {destinationHashBytes :: ByteString}
    deriving (Eq, Ord)

-- | The name is hashed as the bytes it was given, and normalising them
-- makes a different destination.
nameHash :: Name -> NameHash
nameHash = NameHash . B.take Identity.nameHashLength . Identity.fullHash . nameBytes

destinationHash :: NameHash -> Maybe IdentityHash -> DestinationHash
destinationHash hash identity =
    DestinationHash (Identity.truncatedHash (nameHashBytes hash <> material))
  where
    material = maybe B.empty identityHashBytes identity
