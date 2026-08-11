{-# LANGUAGE StrictData #-}

module Reticulum.Transport
    ( PathRequest (..)
    , pathRequest
    , pack
    , uniqueTag
    , accepted
    , counted
    , admitted
    , remembered
    , Route (..)
    , outbound
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust)
import Data.Set (Set)
import qualified Data.Set as Set

import Reticulum.Destination (DestinationHash (DestinationHash))
import Reticulum.Packet (Packet, Rejection (ShortPayload), addressLength)
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Path as Path

data PathRequest = PathRequest
    { wantedHash :: ByteString
    , requesterId :: Maybe ByteString
    , tag :: Maybe ByteString
    }

-- | Nothing delimits the three fields, so a 17-byte tag sent without a
-- requester reads as a requester and a one-byte tag.
pathRequest :: ByteString -> Either Rejection PathRequest
pathRequest payload
    | length' < addressLength = Left (ShortPayload length' addressLength)
    | length' > 2 * addressLength =
        Right
            (request (Just (part addressLength)) (Just (B.drop (2 * addressLength) payload)))
    | length' > addressLength = Right (request Nothing (Just (B.drop addressLength payload)))
    | otherwise = Right (request Nothing Nothing)
  where
    length' = B.length payload
    part at = B.take addressLength (B.drop at payload)
    request = PathRequest (part 0)

pack :: PathRequest -> ByteString
pack request =
    B.concat
        [ wantedHash request
        , fromMaybe B.empty (requesterId request)
        , fromMaybe B.empty (tag request)
        ]

uniqueTag :: PathRequest -> Maybe ByteString
uniqueTag request = mappend (wantedHash request) . B.take addressLength <$> tag request

-- | A request with no tag reaches no duplicate check and is dropped
-- after it has been read.
accepted :: PathRequest -> Bool
accepted = isJust . tag

-- | The count is of hops taken, and reaching this node is one of them.
counted :: Packet -> Packet
counted packet = packet {Packet.hops = Packet.hops packet + 1}

admitted :: ByteString -> Set ByteString -> Packet -> Bool
admitted ours seen packet
    | Just elsewhere <- Packet.transportId packet
    , Packet.packetType packet /= Packet.Announce =
        elsewhere == ours
    | Packet.context packet `elem` carried = True
    | Packet.destinationType packet `elem` [Packet.Plain, Packet.Group] =
        Packet.packetType packet /= Packet.Announce && Packet.hops packet <= 1
    | Packet.packetHash packet `Set.notMember` seen = True
    | otherwise =
        Packet.packetType packet == Packet.Announce
            && Packet.destinationType packet == Packet.Single
  where
    carried =
        [ Packet.Keepalive
        , Packet.ResourceReq
        , Packet.ResourcePrf
        , Packet.Resource
        , Packet.CacheRequest
        , Packet.Channel
        ]

-- | A link request proof is held out of the duplicate check until it is
-- known not to belong further along the chain.
remembered :: Packet -> Bool
remembered packet =
    not
        ( Packet.packetType packet == Packet.Proof
            && Packet.context packet == Packet.LinkRequestProof
        )

-- | A packet the node knows a path for goes out on the one interface
-- that path was heard on, and one already carrying a transport id
-- cannot be given another.
data Route i
    = Along i Packet
    | Everywhere Packet
    | Nowhere

outbound :: Path.Table i -> Packet -> Route i
outbound table packet
    | not routable = Everywhere packet
    | otherwise = case Map.lookup (DestinationHash (Packet.address packet)) table of
        Nothing -> Everywhere packet
        Just path
            | Path.hops path <= 1 -> Along (Path.interface path) packet
            | otherwise -> case Packet.transportId packet of
                Nothing -> Along (Path.interface path) (inserted path)
                Just _ -> Nowhere
  where
    routable =
        Packet.packetType packet /= Packet.Announce
            && Packet.destinationType packet `notElem` [Packet.Plain, Packet.Group]
    inserted path =
        packet
            { Packet.transportId = Just (Path.via path)
            , Packet.transportType = Packet.Transport
            }
