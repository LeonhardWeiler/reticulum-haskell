{-# LANGUAGE StrictData #-}

-- | RNS/Destination.py#announce, RNS/Identity.py#validate_announce
module Reticulum.Announce
    ( Announce (..)
    , announce
    , signedData
    , expectedHash
    , destinationMatch
    , signatureValid
    , randomHashLength
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Maybe (fromMaybe)

import Reticulum.Destination (DestinationHash (destinationHashBytes), NameHash (NameHash))
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Packet as Packet

-- | RNS/Destination.py#announce: five random bytes and five of unix
-- time, big endian. The timestamp is truncated to five bytes rather
-- than being a field five bytes wide, so no announce can be produced a
-- second time.
randomHashLength :: Int
randomHashLength = 10

data Announce = Announce
    { publicKey :: Identity.PublicKey
    , nameHash :: NameHash
    , randomHash :: ByteString
    , ratchet :: Maybe ByteString
    , signature :: ByteString
    , appData :: ByteString
    }

-- | RNS/Identity.py#validate_announce. The ratchet is present when and
-- only when the context flag in the header is set; a receiver that
-- ignores the flag reads its first 32 bytes as the signature.
-- Everything past the signature is app data.
announce :: Packet.Packet -> Either Packet.Rejection Announce
announce packet
    | B.length payload < needed = Left (Packet.ShortPayload (B.length payload) needed)
    | otherwise = case Identity.publicKey (part 0 Identity.keySize) of
        -- Unreachable: the length checked above covers this slice, and
        -- a short one is the same rejection.
        Left _ -> Left (Packet.ShortPayload (B.length payload) needed)
        Right key ->
            Right
                Announce
                    { publicKey = key
                    , nameHash = NameHash (part keyAt Identity.nameHashLength)
                    , randomHash = part randomAt randomHashLength
                    , ratchet =
                        if Packet.contextFlag packet
                            then Just (part ratchetAt Identity.ratchetSize)
                            else Nothing
                    , signature = part signatureAt Identity.signatureLength
                    , appData = B.drop needed payload
                    }
  where
    payload = Packet.payload packet
    part at size = B.take size (B.drop at payload)

    keyAt = Identity.keySize
    randomAt = keyAt + Identity.nameHashLength
    ratchetAt = randomAt + randomHashLength
    signatureAt = ratchetAt + carried Identity.ratchetSize
    needed = signatureAt + Identity.signatureLength
    carried size = if Packet.contextFlag packet then size else 0

-- | RNS/Destination.py#announce on the sending side,
-- RNS/Identity.py#validate_announce on the receiving one.
--
-- Two things differ from the wire layout. The destination hash is
-- signed and is not in the payload: it comes from the header. App data
-- is transmitted after the signature and signed before it.
signedData :: ByteString -> Announce -> ByteString
signedData address value =
    B.concat
        [ address
        , Identity.publicKeyBytes (publicKey value)
        , Destination.nameHashBytes (nameHash value)
        , randomHash value
        , fromMaybe B.empty (ratchet value)
        , appData value
        ]

-- | RNS/Identity.py#expected_hash. The announce carries the name hash
-- and not the name, so a receiver can confirm the destination hash
-- belongs to the announced key without recovering the aspects.
expectedHash :: Announce -> DestinationHash
expectedHash value =
    Destination.destinationHash
        (nameHash value)
        (Just (Identity.identityHash (publicKey value)))

destinationMatch :: ByteString -> Announce -> Bool
destinationMatch address = (address ==) . destinationHashBytes . expectedHash

-- | The first of the two checks, and the one the destination hash is
-- part of: an announce whose header was rewritten fails both.
signatureValid :: ByteString -> Announce -> Bool
signatureValid address value =
    Identity.validate (publicKey value) (signedData address value) (signature value)
