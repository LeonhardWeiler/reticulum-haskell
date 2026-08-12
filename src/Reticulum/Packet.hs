{-# LANGUAGE StrictData #-}

module Reticulum.Packet
    ( Packet (..)
    , unpack
    , pack
    , flags
    , HeaderType (..)
    , headerType
    , headerLength
    , TransportType (..)
    , DestinationType (..)
    , PacketType (..)
    , Context (..)
    , toContext
    , contextByte
    , encrypted
    , hashablePart
    , packetHash
    , addressLength
    , pathfinderM
    ) where

import Data.Bits (bit, shiftL, shiftR, testBit, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Maybe (fromMaybe)
import Data.Word (Word8)

import qualified Reticulum.Identity as Identity
import Reticulum.Rejection (Rejection (HopLimit, ShortHeader))

pathfinderM :: Int
pathfinderM = 128

addressLength :: Int
addressLength = Identity.truncatedHashLength

data HeaderType = Header1 | Header2
    deriving (Eq)

-- | The flags carry one bit for this, so of the four transport types
-- only two fit on the wire.
data TransportType = Broadcast | Transport
    deriving (Eq)

data DestinationType = Single | Group | Plain | Link
    deriving (Eq)

data PacketType = Data | Announce | LinkRequest | Proof
    deriving (Eq)

data Context
    = None
    | Resource
    | ResourceAdv
    | ResourceReq
    | ResourceHmu
    | ResourcePrf
    | ResourceIcl
    | ResourceRcl
    | CacheRequest
    | Request
    | Response
    | PathResponse
    | Command
    | CommandStatus
    | Channel
    | Keepalive
    | LinkIdentify
    | LinkClose
    | LinkProof
    | LinkRtt
    | LinkRequestProof
    | UnnamedContext Word8
    deriving (Eq)

contextByte :: Context -> Word8
contextByte named = case named of
    None -> 0x00
    Resource -> 0x01
    ResourceAdv -> 0x02
    ResourceReq -> 0x03
    ResourceHmu -> 0x04
    ResourcePrf -> 0x05
    ResourceIcl -> 0x06
    ResourceRcl -> 0x07
    CacheRequest -> 0x08
    Request -> 0x09
    Response -> 0x0a
    PathResponse -> 0x0b
    Command -> 0x0c
    CommandStatus -> 0x0d
    Channel -> 0x0e
    Keepalive -> 0xfa
    LinkIdentify -> 0xfb
    LinkClose -> 0xfc
    LinkProof -> 0xfd
    LinkRtt -> 0xfe
    LinkRequestProof -> 0xff
    UnnamedContext value -> value

toContext :: Word8 -> Context
toContext value = case lookup value [(contextByte c, c) | c <- names] of
    Just named -> named
    Nothing -> UnnamedContext value
  where
    names =
        [ None
        , Resource
        , ResourceAdv
        , ResourceReq
        , ResourceHmu
        , ResourcePrf
        , ResourceIcl
        , ResourceRcl
        , CacheRequest
        , Request
        , Response
        , PathResponse
        , Command
        , CommandStatus
        , Channel
        , Keepalive
        , LinkIdentify
        , LinkClose
        , LinkProof
        , LinkRtt
        , LinkRequestProof
        ]

-- | The address is a destination hash for every packet but two: a link
-- request proof carries a link id there and a delivery proof half a
-- packet hash.
data Packet = Packet
    { contextFlag :: Bool
    , transportType :: TransportType
    , destinationType :: DestinationType
    , packetType :: PacketType
    , hops :: Word8
    , transportId :: Maybe ByteString
    , address :: ByteString
    , context :: Context
    , payload :: ByteString
    }

-- | The second header length is what the transport id is carried in, so
-- the two cannot disagree.
headerType :: Packet -> HeaderType
headerType = maybe Header1 (const Header2) . transportId

headerLength :: HeaderType -> Int
headerLength Header1 = 2 + addressLength + 1
headerLength Header2 = 2 + 2 * addressLength + 1

-- | Bit 7 is the interface access code, which a packet does not carry
-- and the frame around it sets.
flags :: Packet -> Word8
flags value =
    header .|. contexted .|. transported .|. destinationBits .|. packetBits
  where
    header = case headerType value of
        Header1 -> 0
        Header2 -> bit 6
    contexted = if contextFlag value then bit 5 else 0
    transported = case transportType value of
        Broadcast -> 0
        Transport -> bit 4
    destinationBits = case destinationType value of
        Single -> 0
        Group -> 1 `shiftL` 2
        Plain -> 2 `shiftL` 2
        Link -> 3 `shiftL` 2
    packetBits = case packetType value of
        Data -> 0
        Announce -> 1
        LinkRequest -> 2
        Proof -> 3

unpack :: ByteString -> Either Rejection Packet
unpack raw = case B.unpack (B.take 2 raw) of
    [flagsByte, hopCount]
        | fromIntegral hopCount >= pathfinderM ->
            Left (HopLimit (fromIntegral hopCount) pathfinderM)
        | otherwise -> case B.uncons (B.drop (addressAt + addressLength) raw) of
            Nothing -> Left (ShortHeader (B.length raw) (headerLength header))
            Just (contextByte', rest) ->
                Right
                    Packet
                        { contextFlag = testBit flagsByte 5
                        , transportType =
                            if testBit flagsByte 4 then Transport else Broadcast
                        , destinationType = destinationTypeOf flagsByte
                        , packetType = packetTypeOf flagsByte
                        , hops = hopCount
                        , transportId = case header of
                            Header1 -> Nothing
                            Header2 -> Just (B.take addressLength (B.drop 2 raw))
                        , address = B.take addressLength (B.drop addressAt raw)
                        , context = toContext contextByte'
                        , payload = rest
                        }
      where
        header = if testBit flagsByte 6 then Header2 else Header1
        addressAt = case header of
            Header1 -> 2
            Header2 -> 2 + addressLength
    _ -> Left (ShortHeader (B.length raw) 2)

pack :: Packet -> ByteString
pack value =
    B.concat
        [ B.pack [flags value, hops value]
        , fromMaybe B.empty (transportId value)
        , address value
        , B.singleton (contextByte (context value))
        , payload value
        ]

-- | A resource takes care of its own encryption, a keepalive carries no
-- data, and the three other kinds of packet are read before a key is
-- known.
encrypted :: Packet -> Bool
encrypted unpacked = case packetType unpacked of
    Announce -> False
    LinkRequest -> False
    Proof -> False
    Data -> case destinationType unpacked of
        Plain -> False
        _ -> context unpacked `notElem` [Resource, Keepalive, CacheRequest]

-- | Neither the hop count nor the transport id is in it, so the hash
-- survives a hop and a transport node rewriting the header.
hashablePart :: Packet -> ByteString
hashablePart unpacked =
    B.concat
        [ B.singleton (flags unpacked .&. 0x0f)
        , address unpacked
        , B.singleton (contextByte (context unpacked))
        , payload unpacked
        ]

packetHash :: Packet -> ByteString
packetHash = Identity.fullHash . hashablePart

destinationTypeOf :: Word8 -> DestinationType
destinationTypeOf flagsByte = case (flagsByte `shiftR` 2) .&. 0x03 of
    0 -> Single
    1 -> Group
    2 -> Plain
    _ -> Link

packetTypeOf :: Word8 -> PacketType
packetTypeOf flagsByte = case flagsByte .&. 0x03 of
    0 -> Data
    1 -> Announce
    2 -> LinkRequest
    _ -> Proof
