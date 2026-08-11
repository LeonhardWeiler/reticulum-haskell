{-# LANGUAGE StrictData #-}

module Reticulum.Link
    ( Request (..)
    , request
    , packRequest
    , RequestProof (..)
    , requestProof
    , packRequestProof
    , signedData
    , signatureValid
    , Handshake (..)
    , handshake
    , answered
    , sealed
    , opened
    , Identify (..)
    , identify
    , identifySigned
    , identifyValid
    , mode
    , mtu
    , transmissionUnit
    , capacity
    , partSize
    , linkId
    , publicKeysLength
    , signallingSize
    , modeAes256Cbc
    ) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Maybe (fromMaybe)
import Data.Word (Word8)

import qualified Reticulum.Encryption as Encryption
import qualified Reticulum.Identity as Identity
import Reticulum.Packet (Rejection (SignalledLength))
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Token as Token

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
    , requestSignalling :: Maybe ByteString
    }

request :: ByteString -> Either Rejection Request
request payload
    | length' == publicKeysLength = Right (drawn Nothing)
    | length' == publicKeysLength + signallingSize =
        Right (drawn (Just (B.drop publicKeysLength payload)))
    | otherwise =
        Left (SignalledLength length' publicKeysLength (publicKeysLength + signallingSize))
  where
    length' = B.length payload
    half = publicKeysLength `div` 2
    drawn = Request (B.take half payload) (B.take half (B.drop half payload))

packRequest :: Request -> ByteString
packRequest value =
    B.concat
        [ x25519Public value
        , ed25519Public value
        , fromMaybe B.empty (requestSignalling value)
        ]

-- | The responder's Ed25519 key is in no packet, and only the half the
-- initiator needs for the agreement is sent.
data RequestProof = RequestProof
    { signature :: ByteString
    , responderPublic :: ByteString
    , proofSignalling :: Maybe ByteString
    }

requestProof :: ByteString -> Either Rejection RequestProof
requestProof payload
    | length' == proofLength = Right (parts Nothing)
    | length' == proofLength + signallingSize =
        Right (parts (Just (B.drop proofLength payload)))
    | otherwise = Left (SignalledLength length' proofLength (proofLength + signallingSize))
  where
    length' = B.length payload
    parts =
        RequestProof
            (B.take Identity.signatureLength payload)
            (B.take (publicKeysLength `div` 2) (B.drop Identity.signatureLength payload))

packRequestProof :: RequestProof -> ByteString
packRequestProof value =
    B.concat
        [ signature value
        , responderPublic value
        , fromMaybe B.empty (proofSignalling value)
        ]

proofLength :: Int
proofLength = Identity.signatureLength + publicKeysLength `div` 2

signedData :: ByteString -> ByteString -> RequestProof -> ByteString
signedData link signer value =
    B.concat
        [ link
        , responderPublic value
        , signer
        , fromMaybe B.empty (proofSignalling value)
        ]

signatureValid :: ByteString -> ByteString -> RequestProof -> Bool
signatureValid link signer value =
    Identity.verify signer (signedData link signer value) (signature value)

data Handshake = Handshake
    { shared :: ByteString
    , keys :: Token.Keys
    }

-- | The salt is the link id, which no packet on the link carries.
handshake :: ByteString -> ByteString -> ByteString -> Maybe Handshake
handshake own peer link = derived <$> Encryption.shared own peer
  where
    derived agreed =
        Handshake agreed (Token.keys (Encryption.derive Encryption.derivedKeyLength agreed link))

-- | The point that goes back is this end's own ephemeral one, and the
-- key that signs it is the destination's.
answered
    :: Identity.PrivateKey
    -> ByteString
    -> ByteString
    -> Request
    -> Either String (Handshake, RequestProof)
answered secret ephemeral link asked = do
    point <- note "the ephemeral scalar" (Encryption.publicPoint ephemeral)
    shook <- note "the agreement" (handshake ephemeral (x25519Public asked) link)
    key <- Identity.toPublic secret
    let body = RequestProof B.empty point (requestSignalling asked)
    signed <- Identity.sign secret (signedData link (Identity.ed25519Public key) body)
    pure (shook, body {signature = signed})
  where
    note what = maybe (Left (what ++ " is not on the curve")) Right

sealed :: Token.Keys -> ByteString -> ByteString -> Maybe ByteString
sealed key vector plain = Token.pack <$> Token.seal key vector plain

opened :: Token.Keys -> ByteString -> Maybe ByteString
opened key body = Token.open key =<< either (const Nothing) Just (Token.token body)

data Identify = Identify
    { identityPublic :: Identity.PublicKey
    , identitySignature :: ByteString
    }

identify :: ByteString -> Maybe Identify
identify plain
    | B.length plain == Identity.keySize + Identity.signatureLength =
        flip Identify (B.drop Identity.keySize plain)
            <$> either (const Nothing) Just (Identity.publicKey (B.take Identity.keySize plain))
    | otherwise = Nothing

-- | The link id is signed, so an identify cannot be lifted onto another
-- link.
identifySigned :: ByteString -> Identify -> ByteString
identifySigned link value = link <> Identity.publicKeyBytes (identityPublic value)

identifyValid :: ByteString -> Identify -> Bool
identifyValid link value =
    Identity.validate (identityPublic value) (identifySigned link value) (identitySignature value)

-- | The decoder returns the three bits it read whatever they are, and
-- a packet that signals nothing reads as the one mode the reference
-- enables.
mode :: Maybe ByteString -> Word8
mode signalled = case B.uncons =<< signalled of
    Just (byte, _) -> (byte .&. modeBytemask) `shiftR` 5
    Nothing -> modeAes256Cbc

mtu :: Maybe ByteString -> Maybe Int
mtu = fmap ((.&. mtuBytemask) . bigEndian)

transmissionUnit :: Maybe ByteString -> Int
transmissionUnit = fromMaybe defaultUnit . mtu

defaultUnit :: Int
defaultUnit = 500

-- | The whole transmission unit less the header, the token around the
-- plaintext and the byte an interface may take, rounded down to the
-- block the padding fills.
capacity :: Int -> Int
capacity unit = whole `div` Token.blockSize * Token.blockSize - 1
  where
    whole = unit - accessCodeSize - Packet.headerLength Packet.Header1 - Token.tokenOverhead

-- | One part of a resource is measured against the longest header a
-- packet can carry, whether it carries one or not.
partSize :: Int -> Int
partSize unit = unit - accessCodeSize - Packet.headerLength Packet.Header2

accessCodeSize :: Int
accessCodeSize = 1

bigEndian :: ByteString -> Int
bigEndian = B.foldl' (\value byte -> (value `shiftL` 8) .|. fromIntegral byte) 0

-- | The signalling bytes are cut off the end, so a request that signals
-- an MTU opens the link a request without one opens.
linkId :: Packet.Packet -> ByteString
linkId unpacked = Identity.truncatedHash (B.take (B.length part - signalled) part)
  where
    part = Packet.hashablePart unpacked
    signalled = max 0 (B.length (Packet.payload unpacked) - publicKeysLength)
