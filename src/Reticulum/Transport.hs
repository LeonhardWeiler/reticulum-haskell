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
    , relayed
    , Crossing (..)
    , Links
    , crossing
    , alongLink
    , Proven (..)
    , proofed
    , aged
    , Return (..)
    , Reverse
    , remember
    , returned
    , forgotten
    , Pending (..)
    , Waiting
    , queued
    , due
    , rebroadcast
    , overheard
    , window
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Word (Word8)

import Reticulum.Destination (DestinationHash (DestinationHash))
import qualified Reticulum.Link as Link
import Reticulum.Packet (Packet, Rejection (ShortPayload), addressLength)
import qualified Reticulum.Packet as Packet
import Reticulum.Path (Time (Time, seconds))
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
-- known not to belong further along the chain, and a packet on a link
-- crossing this node may be seen before its turn.
remembered :: Links i -> Packet -> Bool
remembered links packet =
    not
        ( Packet.packetType packet == Packet.Proof
            && Packet.context packet == Packet.LinkRequestProof
        )
        && Packet.address packet `Map.notMember` links

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

-- | The hop this node was named as, and the one written in its place:
-- the last hop before the destination carries no transport id at all.
relayed :: ByteString -> Path.Table i -> Packet -> Maybe (Path.Path i, Packet)
relayed ours table packet
    | Packet.packetType packet == Packet.Announce = Nothing
    | Packet.transportId packet /= Just ours = Nothing
    | otherwise = onward <$> Map.lookup (DestinationHash (Packet.address packet)) table
  where
    onward path = (path, carried path)
    carried path
        | Path.hops path > 1 = packet {Packet.transportId = Just (Path.via path)}
        | Path.hops path == 1 =
            packet
                { Packet.transportId = Nothing
                , Packet.transportType = Packet.Broadcast
                }
        | otherwise = packet

perHopTimeout :: Double
perHopTimeout = 6

linkLifetime :: Double
linkLifetime = 900

-- | What a link crossing this node leaves behind: the two interfaces it
-- runs between and the hop count each side arrives with.
data Crossing i = Crossing
    { hop :: ByteString
    , ahead :: i
    , farther :: Word8
    , behind :: i
    , nearer :: Word8
    , between :: DestinationHash
    , proven :: Bool
    , deadline :: Time
    , stamp :: Time
    }

type Links i = Map ByteString (Crossing i)

crossing :: Time -> i -> Path.Path i -> Packet -> Links i -> Links i
crossing now through path packet links
    | Packet.packetType packet /= Packet.LinkRequest = links
    | otherwise = Map.insert (Link.linkId packet) entry links
  where
    entry =
        Crossing
            { hop = Path.via path
            , ahead = Path.interface path
            , farther = Path.hops path
            , behind = through
            , nearer = Packet.hops packet
            , between = DestinationHash (Packet.address packet)
            , proven = False
            , deadline = later now (perHopTimeout * fromIntegral (max 1 (Path.hops path)))
            , stamp = now
            }

-- | A packet on a link goes out the side it did not come in on, and one
-- interface carrying both sides tells them apart by hop count alone.
alongLink :: Eq i => Time -> i -> Packet -> Links i -> (Maybe i, Links i)
alongLink now through packet links
    | Packet.packetType packet `elem` [Packet.Announce, Packet.LinkRequest] = (Nothing, links)
    | Packet.context packet == Packet.LinkRequestProof = (Nothing, links)
    | otherwise = case Map.lookup (Packet.address packet) links of
        Nothing -> (Nothing, links)
        Just entry -> case direction entry of
            Nothing -> (Nothing, links)
            Just out ->
                ( Just out
                , Map.insert (Packet.address packet) entry {stamp = now} links
                )
  where
    direction entry
        | ahead entry == behind entry =
            if Packet.hops packet `elem` [farther entry, nearer entry]
                then Just (ahead entry)
                else Nothing
        | through == ahead entry =
            if Packet.hops packet == farther entry then Just (behind entry) else Nothing
        | through == behind entry =
            if Packet.hops packet == nearer entry then Just (ahead entry) else Nothing
        | otherwise = Nothing

data Proven i = Proven
    { back :: i
    , rebalanced :: Maybe (DestinationHash, Word8)
    }

-- | The proof for a link crossing this node is checked here, and the
-- hop count it arrives with corrects what was written down, once.
proofed :: Eq i => (DestinationHash -> Bool) -> i -> Packet -> Links i -> (Maybe (Proven i), Links i)
proofed valid through packet links = case Map.lookup key links of
    Nothing -> (Nothing, links)
    Just entry
        | through /= ahead entry -> (Nothing, links)
        | not (valid (between entry)) -> (Nothing, links)
        | Packet.hops packet == farther entry ->
            (Just (Proven (behind entry) Nothing), settled entry)
        | not (proven entry) ->
            ( Just (Proven (behind entry) (Just (between entry, Packet.hops packet)))
            , settled entry {farther = Packet.hops packet}
            )
        | otherwise -> (Nothing, links)
  where
    key = Packet.address packet
    settled entry = Map.insert key entry {proven = True} links

-- | A link that was never proved is given the time its request needed,
-- and one that was is kept as long as it could still carry a packet.
aged :: Time -> Links i -> Links i
aged now = Map.filter alive
  where
    alive entry
        | proven entry = seconds (stamp entry) + linkLifetime > seconds now
        | otherwise = seconds (deadline entry) > seconds now

data Return i = Return
    { inward :: i
    , outward :: i
    , since :: Time
    }

type Reverse i = Map ByteString (Return i)

reverseLifetime :: Double
reverseLifetime = 8 * 60

-- | A link request is answered along the link table and leaves nothing
-- here.
remember :: i -> i -> Time -> Packet -> Reverse i -> Reverse i
remember from to now packet held
    | Packet.packetType packet == Packet.LinkRequest = held
    | otherwise = Map.insert (trace packet) (Return from to now) held

-- | The proof carries half the hash of the packet it is for, and comes
-- back on the interface that packet went out on or not at all.
returned :: Eq i => i -> Packet -> Reverse i -> (Maybe i, Reverse i)
returned through packet held = case Map.lookup (Packet.address packet) held of
    Nothing -> (Nothing, held)
    Just entry ->
        ( if outward entry == through then Just (inward entry) else Nothing
        , Map.delete (Packet.address packet) held
        )

forgotten :: Time -> Reverse i -> Reverse i
forgotten now = Map.filter ((> seconds now) . (+ reverseLifetime) . seconds . since)

trace :: Packet -> ByteString
trace = B.take addressLength . Packet.packetHash

retransmits :: Int
retransmits = 1

grace :: Double
grace = 5

-- | The wait before a rebroadcast is spread across this many seconds so
-- that two nodes hearing one announce do not answer together.
window :: Double
window = 0.5

localRebroadcasts :: Int
localRebroadcasts = 2

data Pending i = Pending
    { announce :: Packet
    , sendAt :: Time
    , retries :: Int
    , rebroadcasts :: Int
    , blocked :: Bool
    , travelled :: Word8
    , arrived :: i
    , toward :: Maybe i
    }

type Waiting i = Map DestinationHash (Pending i)

-- | A path response answers one request and is not carried further.
queued :: Time -> Double -> i -> Packet -> Maybe (Pending i)
queued now spread through packet
    | Packet.context packet == Packet.PathResponse = Nothing
    | otherwise =
        Just
            Pending
                { announce = packet
                , sendAt = later now spread
                , retries = 0
                , rebroadcasts = 0
                , blocked = False
                , travelled = Packet.hops packet
                , arrived = through
                , toward = Nothing
                }

due :: Time -> Waiting i -> ([Pending i], Waiting i)
due now = Map.foldrWithKey step ([], Map.empty)
  where
    step destination entry (sending, kept)
        | retries entry > retransmits = (sending, kept)
        | sendAt entry > now = (sending, Map.insert destination entry kept)
        | otherwise = (entry : sending, Map.insert destination (again entry) kept)
    again entry =
        entry {sendAt = later now (grace + window), retries = retries entry + 1}

rebroadcast :: ByteString -> Pending i -> Packet
rebroadcast ours entry =
    (announce entry)
        { Packet.transportType = Packet.Transport
        , Packet.transportId = Just ours
        , Packet.hops = travelled entry
        , Packet.context = if blocked entry then Packet.PathResponse else Packet.None
        }

-- | One hop further along is another node doing what this one was going
-- to do, and two is that node's own rebroadcast coming back.
overheard :: Time -> Packet -> Waiting i -> Waiting i
overheard now packet waiting
    | isJust (Packet.transportId packet) = Map.update kept destination waiting
    | otherwise = waiting
  where
    destination = DestinationHash (Packet.address packet)
    kept entry
        | Packet.hops packet == travelled entry + 2
        , retries entry > 0
        , now < sendAt entry =
            Nothing
        | Packet.hops packet == travelled entry + 1 =
            if retries entry > 0 && grown entry >= localRebroadcasts
                then Nothing
                else Just entry {rebroadcasts = grown entry}
        | otherwise = Just entry
    grown entry = rebroadcasts entry + 1

later :: Time -> Double -> Time
later now offset = Time (seconds now + offset)
