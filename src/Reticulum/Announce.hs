{-# LANGUAGE StrictData #-}

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

-- | Five random bytes and five of unix time, big endian.
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

announce :: Packet.Packet -> Either Packet.Rejection Announce
announce packet
    | B.length payload < needed = Left (Packet.ShortPayload (B.length payload) needed)
    | otherwise = case Identity.publicKey (part 0 Identity.keySize) of
        -- The length above covers this slice, and a short one is the
        -- same rejection.
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

-- | App data travels after the signature and is signed before it, and
-- the address is signed without being in the payload at all.
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

expectedHash :: Announce -> DestinationHash
expectedHash value =
    Destination.destinationHash
        (nameHash value)
        (Just (Identity.identityHash (publicKey value)))

destinationMatch :: ByteString -> Announce -> Bool
destinationMatch address = (address ==) . destinationHashBytes . expectedHash

signatureValid :: ByteString -> Announce -> Bool
signatureValid address value =
    Identity.validate (publicKey value) (signedData address value) (signature value)
