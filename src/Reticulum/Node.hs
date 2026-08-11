{-# LANGUAGE StrictData #-}

module Reticulum.Node
    ( Interface (name, transmit)
    , interface
    , Settings (..)
    , Answering (..)
    , Node
    , start
    , stop
    , attach
    , detach
    , inbound
    , send
    , serve
    , announce
    , requestPath
    , paths
    , clock
    , keypair
    ) where

import Control.Concurrent (ThreadId, forkIO, killThread, threadDelay)
import Control.Concurrent.MVar (MVar, modifyMVar, modifyMVar_, newMVar, readMVar)
import Control.Monad (forever, when)
import qualified Crypto.Random.Entropy as Entropy
import Data.Bits (shiftR, testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Unique (Unique, newUnique)
import Data.Word (Word64, Word8)
import System.IO (hPutStrLn, stderr)

import Reticulum.Announce (Announce)
import qualified Reticulum.Announce as Announce
import Reticulum.Destination (DestinationHash (DestinationHash, destinationHashBytes), Name)
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Encryption as Encryption
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Link as Link
import Reticulum.Packet (Packet (Packet))
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Path as Path
import qualified Reticulum.Request as Request
import qualified Reticulum.Token as Token
import qualified Reticulum.Transport as Transport

-- | Two interfaces of the same name are two of them, so what tells them
-- apart is handed out once and never read.
data Interface = Interface
    { name :: String
    , transmit :: ByteString -> IO ()
    , token :: Unique
    }

instance Eq Interface where
    one == other = token one == token other

interface :: String -> (ByteString -> IO ()) -> IO Interface
interface named write = Interface named write <$> newUnique

data Settings = Settings
    { transport :: Bool
    }

-- | What a destination of this node's own does with what arrives for
-- it, and what it answers on each path it serves.
data Answering = Answering
    { delivered :: ByteString -> IO ()
    , requested :: Map ByteString (ByteString -> IO (Maybe ByteString))
    }

data Local = Local
    { nameHash :: Destination.NameHash
    , appData :: ByteString
    , answers :: Answering
    }

-- | A link this node answered: the keys the handshake made, the one
-- interface it is allowed to arrive on, and who the far end said it is.
data Session = Session
    { keys :: Token.Keys
    , at :: Interface
    , since :: Path.Time
    , holds :: Int
    , serving :: Local
    , identified :: Maybe Identity.PublicKey
    }

data Node = Node
    { identity :: Identity.PrivateKey
    , public :: Identity.PublicKey
    , ours :: ByteString
    , settings :: Settings
    , attached :: MVar [Interface]
    , table :: MVar (Path.Table Interface)
    , waiting :: MVar (Transport.Waiting Interface)
    , returns :: MVar (Transport.Reverse Interface)
    , links :: MVar (Transport.Links Interface)
    , announces :: MVar (Map DestinationHash Packet)
    , seen :: MVar (Set ByteString)
    , local :: MVar (Map DestinationHash Local)
    , sessions :: MVar (Map ByteString Session)
    , requests :: MVar (Set ByteString)
    , heard :: DestinationHash -> Announce -> Path.Path Interface -> IO ()
    , sweeper :: Maybe ThreadId
    }

start
    :: Settings
    -> Identity.PrivateKey
    -> (DestinationHash -> Announce -> Path.Path Interface -> IO ())
    -> IO (Either String Node)
start how private handler = case Identity.toPublic private of
    Left reason -> pure (Left reason)
    Right key -> do
        node <-
            Node private key (Identity.identityHashBytes (Identity.identityHash key)) how
                <$> newMVar []
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Set.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Set.empty
        let built = node handler Nothing
        thread <- forkIO (forever (threadDelay sweepInterval >> sweep built))
        pure (Right built {sweeper = Just thread})

stop :: Node -> IO ()
stop = maybe (pure ()) killThread . sweeper

attach :: Node -> Interface -> IO ()
attach node through = modifyMVar_ (attached node) (pure . (++ [through]))

detach :: Node -> Interface -> IO ()
detach node through = modifyMVar_ (attached node) (pure . filter (/= through))

paths :: Node -> IO (Path.Table Interface)
paths = readMVar . table

clock :: IO Path.Time
clock = Path.Time . realToFrac <$> getPOSIXTime

-- | An interface told no access code drops what carries one.
inbound :: Node -> Interface -> ByteString -> IO ()
inbound node through raw
    | maybe True (\(flags, _) -> testBit flags 7) (B.uncons raw) = pure ()
    | otherwise = case Packet.unpack raw of
        Left _ -> pure ()
        Right packet -> taken node through (Transport.counted packet)

taken :: Node -> Interface -> Packet -> IO ()
taken node through packet = do
    crossings <- readMVar (links node)
    allowed <- modifyMVar (seen node) (pure . filtered crossings)
    when allowed (sorted node through packet)
  where
    filtered crossings hashes
        | not verdict = (hashes, False)
        | Transport.remembered crossings packet =
            (Set.insert (Packet.packetHash packet) hashes, True)
        | otherwise = (hashes, True)
      where
        verdict = Transport.admitted (ours node) hashes packet

sorted :: Node -> Interface -> Packet -> IO ()
sorted node through packet
    | Packet.packetType packet == Packet.Announce = announced node through packet
    | Packet.address packet == Transport.pathRequestAddress = asked node through packet
    | otherwise = do
        mine <- readMVar (local node)
        open <- readMVar (sessions node)
        case Map.lookup (DestinationHash (Packet.address packet)) mine of
            Just held -> arrived node through held packet
            Nothing -> case Map.lookup (Packet.address packet) open of
                Just session -> spoken node through session packet
                Nothing -> forwarding node (relay node through packet)

-- | A packet for a destination of this node's own goes no further.
arrived :: Node -> Interface -> Local -> Packet -> IO ()
arrived node through held packet
    | Packet.packetType packet == Packet.LinkRequest = opening node through held packet
    | Packet.packetType packet /= Packet.Data = pure ()
    | Packet.destinationType packet /= Packet.Single = pure ()
    | otherwise = case unsealed node (Packet.payload packet) of
        Nothing -> pure ()
        Just plain -> do
            delivered (answers held) plain
            prove node through packet

-- | Only the one mode this end derives keys for is answered.
opening :: Node -> Interface -> Local -> Packet -> IO ()
opening node through held packet = case Link.request (Packet.payload packet) of
    Left _ -> pure ()
    Right wanted
        | Link.mode (Link.requestSignalling wanted) /= Link.modeAes256Cbc -> pure ()
        | otherwise -> do
            ephemeral <- Entropy.getEntropy Encryption.ephemeralLength
            now <- clock
            case Link.answered (identity node) ephemeral link wanted of
                Left reason -> hPutStrLn stderr ("link: " ++ reason)
                Right (shook, body) -> do
                    let signalled = Link.requestSignalling wanted
                    modifyMVar_ (sessions node) (pure . Map.insert link (begun shook now signalled))
                    transmit through (Packet.pack (written body))
  where
    link = Link.linkId packet
    begun shook now signalled =
        Session
            { keys = Link.keys shook
            , at = through
            , since = now
            , holds = Link.capacity signalled
            , serving = held
            , identified = Nothing
            }
    written body =
        onLink link Packet.Proof Packet.LinkRequestProof (Link.packRequestProof body)

onLink :: ByteString -> Packet.PacketType -> Packet.Context -> ByteString -> Packet
onLink link kind told body =
    Packet
        { Packet.contextFlag = False
        , Packet.transportType = Packet.Broadcast
        , Packet.destinationType = Packet.Link
        , Packet.packetType = kind
        , Packet.hops = 0
        , Packet.transportId = Nothing
        , Packet.address = link
        , Packet.context = told
        , Packet.payload = body
        }

-- | A link packet that arrives on another interface than the one the
-- link was answered on is not on that link.
spoken :: Node -> Interface -> Session -> Packet -> IO ()
spoken node through session packet
    | through /= at session = pure ()
    | Packet.packetType packet /= Packet.Data = pure ()
    | otherwise = do
        now <- clock
        modifyMVar_ (sessions node) (pure . Map.adjust (\held -> held {since = now}) link)
        case Packet.context packet of
            Packet.Keepalive -> when (Packet.payload packet == B.singleton alive) answering
            Packet.None -> mapM_ took (opened (Packet.payload packet))
            Packet.LinkIdentify -> mapM_ names (opened (Packet.payload packet))
            Packet.LinkClose -> mapM_ closes (opened (Packet.payload packet))
            Packet.Request -> mapM_ (asking session packet) (opened (Packet.payload packet))
            _ -> pure ()
  where
    link = Packet.address packet
    opened = Link.opened (keys session)
    answering = transmit through (Packet.pack (onLink link Packet.Data Packet.Keepalive awake))
    took plain = do
        delivered (answers (serving session)) plain
        proveOnLink node session packet
    names plain = case Link.identify plain of
        Just who
            | Link.identifyValid link who ->
                modifyMVar_
                    (sessions node)
                    (pure . Map.adjust (\held -> held {identified = Just (Link.identityPublic who)}) link)
        _ -> pure ()
    closes plain = when (plain == link) (modifyMVar_ (sessions node) (pure . Map.delete link))

-- | The one packet on a link that carries no token, and the two bytes
-- that are the whole exchange.
alive :: Word8
alive = 0xff

awake :: ByteString
awake = B.singleton 0xfe

-- | The request is answered under the id of the packet that asked, and
-- a path this destination does not serve is not answered at all.
asking :: Session -> Packet -> ByteString -> IO ()
asking session packet plain = case Request.request plain of
    Left _ -> pure ()
    Right wanted -> case served =<< Request.pathHash wanted of
        Nothing -> pure ()
        Just answering -> do
            given <- answering (fromMaybe B.empty (Request.requestBody wanted))
            mapM_ (responding session (Packet.address packet) identifier) given
  where
    served path = Map.lookup path (requested (answers (serving session)))
    identifier = Identity.truncatedHash (Packet.hashablePart packet)

-- | An answer that does not fit in one packet on this link is not one
-- this node can send.
responding :: Session -> ByteString -> ByteString -> ByteString -> IO ()
responding session link identifier body
    | B.length packed > holds session =
        hPutStrLn stderr ("response: " ++ show (B.length packed) ++ " bytes")
    | otherwise = do
        vector <- Entropy.getEntropy Token.blockSize
        case Link.sealed (keys session) vector packed of
            Nothing -> hPutStrLn stderr "response: nothing was sealed"
            Just sealed ->
                transmit (at session) (Packet.pack (onLink link Packet.Data Packet.Response sealed))
  where
    packed = Request.packResponse identifier body

-- | A proof on a link carries the hash it proves, which one from a
-- destination does not.
proveOnLink :: Node -> Session -> Packet -> IO ()
proveOnLink node session packet = case Identity.sign (identity node) hash of
    Left reason -> hPutStrLn stderr ("proof: " ++ reason)
    Right signed ->
        transmit
            (at session)
            (Packet.pack (onLink (Packet.address packet) Packet.Proof Packet.None (hash <> signed)))
  where
    hash = Packet.packetHash packet

unsealed :: Node -> ByteString -> Maybe ByteString
unsealed node body = do
    parts <- either (const Nothing) Just (Encryption.encrypted body)
    Encryption.opened (Identity.x25519Private (identity node)) (ours node) parts

-- | The proof is addressed to the first half of the hash of the packet
-- it proves, and carries a signature and nothing else.
prove :: Node -> Interface -> Packet -> IO ()
prove node through packet = case Identity.sign (identity node) hash of
    Left reason -> hPutStrLn stderr ("proof: " ++ reason)
    Right signed -> transmit through (Packet.pack (written signed))
  where
    hash = Packet.packetHash packet
    written signed =
        Packet
            { Packet.contextFlag = False
            , Packet.transportType = Packet.Broadcast
            , Packet.destinationType = Packet.Single
            , Packet.packetType = Packet.Proof
            , Packet.hops = 0
            , Packet.transportId = Nothing
            , Packet.address = B.take Packet.addressLength hash
            , Packet.context = Packet.None
            , Packet.payload = signed
            }

announced :: Node -> Interface -> Packet -> IO ()
announced node through packet = case Announce.announce packet of
    Left _ -> pure ()
    Right carried
        | not (Announce.destinationMatch address carried) -> pure ()
        | not (Announce.signatureValid address carried) -> pure ()
        | otherwise -> do
            mine <- readMVar (local node)
            when (destination `Map.notMember` mine) $ do
                now <- clock
                forwarding node (modifyMVar_ (waiting node) (pure . Transport.overheard now packet))
                learned <- modifyMVar (table node) (pure . took now (entry carried))
                case learned of
                    Nothing -> pure ()
                    Just path -> do
                        modifyMVar_ (announces node) (pure . Map.insert destination packet)
                        forwarding node (queue node now through packet)
                        heard node destination carried path
  where
    address = Packet.address packet
    destination = DestinationHash address
    took now arrival known = case Path.learn now destination arrival known of
        Nothing -> (known, Nothing)
        Just (path, fresh) -> (fresh, Just path)
    entry carried =
        Path.Heard
            { Path.sender = fromMaybe address (Packet.transportId packet)
            , Path.travelled = Packet.hops packet
            , Path.blob = Announce.randomHash carried
            , Path.announceHash = Packet.packetHash packet
            , Path.through = through
            }

forwarding :: Node -> IO () -> IO ()
forwarding node action = when (transport (settings node)) action

queue :: Node -> Path.Time -> Interface -> Packet -> IO ()
queue node now through packet = do
    across <- spread
    case Transport.queued now across through packet of
        Nothing -> pure ()
        Just entry ->
            modifyMVar_
                (waiting node)
                (pure . Map.insert (DestinationHash (Packet.address packet)) entry)

-- | This node was named as the next hop, and where the packet goes
-- after it is the path table's answer; a proof for what it passed on
-- goes back the way that packet came.
relay :: Node -> Interface -> Packet -> IO ()
relay node through packet = do
    reachable <- readMVar (table node)
    now <- clock
    case Transport.relayed (ours node) reachable packet of
        Just (path, onward) -> do
            modifyMVar_
                (returns node)
                (pure . Transport.remember through (Path.interface path) now packet)
            modifyMVar_ (links node) (pure . Transport.crossing now through path packet)
            transmit (Path.interface path) (Packet.pack onward)
        Nothing
            | Packet.context packet == Packet.LinkRequestProof -> settled node through packet
            | Packet.packetType packet == Packet.Proof -> do
                back <- modifyMVar (returns node) (pure . swapped . Transport.returned through packet)
                mapM_ (\out -> transmit out (Packet.pack packet)) back
            | otherwise -> do
                out <- modifyMVar (links node) (pure . swapped . Transport.alongLink now through packet)
                case out of
                    Nothing -> pure ()
                    Just onward -> do
                        modifyMVar_ (seen node) (pure . Set.insert (Packet.packetHash packet))
                        transmit onward (Packet.pack packet)

-- | The proof for a link this node is in the middle of is checked with
-- the key the announce for that destination carried.
settled :: Node -> Interface -> Packet -> IO ()
settled node through packet = do
    cached <- readMVar (announces node)
    outcome <-
        modifyMVar (links node) (pure . swapped . Transport.proofed (valid cached) through packet)
    case outcome of
        Nothing -> pure ()
        Just crossed -> do
            mapM_ (adjusted node) (Transport.rebalanced crossed)
            transmit (Transport.back crossed) (Packet.pack packet)
  where
    valid cached destination = case Map.lookup destination cached of
        Nothing -> False
        Just announcement -> case Announce.announce announcement of
            Left _ -> False
            Right carried -> case Link.requestProof (Packet.payload packet) of
                Left _ -> False
                Right proof ->
                    Link.signatureValid
                        (Packet.address packet)
                        (Identity.ed25519Public (Announce.publicKey carried))
                        proof

adjusted :: Node -> (DestinationHash, Word8) -> IO ()
adjusted node (destination, away) =
    modifyMVar_ (table node) (pure . Path.shorten away destination)

sweepInterval :: Int
sweepInterval = 1000 * 1000

sweep :: Node -> IO ()
sweep node = do
    now <- clock
    interfaces <- readMVar (attached node)
    sending <- modifyMVar (waiting node) (pure . swapped . Transport.due now)
    mapM_ (rebroadcast node) sending
    modifyMVar_ (returns node) (pure . Transport.forgotten now interfaces)
    modifyMVar_ (links node) (pure . Transport.aged now interfaces)
    modifyMVar_ (sessions node) (pure . Map.filter (open now interfaces))
  where
    open now interfaces session =
        Path.seconds (since session) + staleTime > Path.seconds now
            && at session `elem` interfaces

keepalive :: Double
keepalive = 360

staleTime :: Double
staleTime = 2 * keepalive

swapped :: (a, b) -> (b, a)
swapped (one, other) = (other, one)

-- | The one interface an announce is not carried back onto is the one it
-- was heard on.
rebroadcast :: Node -> Transport.Pending Interface -> IO ()
rebroadcast node entry = do
    interfaces <- readMVar (attached node)
    mapM_ (\through -> transmit through raw) (targets interfaces)
  where
    raw = Packet.pack (Transport.rebroadcast (ours node) entry)
    targets interfaces = case Transport.toward entry of
        Just one -> [one]
        Nothing -> filter (/= Transport.arrived entry) interfaces

send :: Node -> Packet -> IO ()
send node packet = do
    reachable <- readMVar (table node)
    case Transport.outbound reachable packet of
        Transport.Along through outgoing -> transmit through (Packet.pack outgoing)
        Transport.Everywhere outgoing -> do
            interfaces <- readMVar (attached node)
            mapM_ (\through -> transmit through (Packet.pack outgoing)) interfaces
        Transport.Nowhere -> pure ()

serve :: Node -> Name -> ByteString -> Answering -> IO DestinationHash
serve node called carried answering = do
    modifyMVar_ (local node) (pure . Map.insert destination held)
    pure destination
  where
    hash = Destination.nameHash called
    destination = whose node hash
    held = Local {nameHash = hash, appData = carried, answers = answering}

announce :: Node -> DestinationHash -> IO ()
announce node destination = do
    mine <- readMVar (local node)
    mapM_ (\held -> emit node held Packet.None Nothing) (Map.lookup destination mine)

whose :: Node -> Destination.NameHash -> DestinationHash
whose node hash =
    Destination.destinationHash hash (Just (Identity.identityHash (public node)))

emit :: Node -> Local -> Packet.Context -> Maybe Interface -> IO ()
emit node held told toward = do
    random <- randomHash
    case built random of
        Left reason -> hPutStrLn stderr ("announce: " ++ reason)
        Right packet -> case toward of
            Nothing -> send node packet
            Just through -> transmit through (Packet.pack packet)
  where
    hash = nameHash held
    destination = whose node hash
    built random = do
        body <- Announce.emitted (identity node) destination hash random (appData held)
        pure
            Packet
                { Packet.contextFlag = False
                , Packet.transportType = Packet.Broadcast
                , Packet.destinationType = Packet.Single
                , Packet.packetType = Packet.Announce
                , Packet.hops = 0
                , Packet.transportId = Nothing
                , Packet.address = destinationHashBytes destination
                , Packet.context = told
                , Packet.payload = Announce.pack body
                }

-- | A request with no tag reaches no duplicate check, and one already
-- answered is answered once.
asked :: Node -> Interface -> Packet -> IO ()
asked node through packet = case Transport.pathRequest (Packet.payload packet) of
    Left _ -> pure ()
    Right wanted
        | not (Transport.accepted wanted) -> pure ()
        | otherwise -> do
            first <- modifyMVar (requests node) (pure . noted wanted)
            when first (answer node through wanted)
  where
    noted wanted tags = case Transport.uniqueTag wanted of
        Nothing -> (tags, False)
        Just unique -> (Set.insert unique tags, unique `Set.notMember` tags)

-- | A destination of this node's own is announced again; one it only
-- knows a path to is answered with the announce that path was learned
-- from, and never toward the node the path runs through.
answer :: Node -> Interface -> Transport.PathRequest -> IO ()
answer node through wanted = do
    mine <- readMVar (local node)
    case Map.lookup destination mine of
        Just held -> emit node held Packet.PathResponse (Just through)
        Nothing -> forwarding node $ do
            reachable <- readMVar (table node)
            cached <- readMVar (announces node)
            now <- clock
            case (Map.lookup destination reachable, Map.lookup destination cached) of
                (Just path, Just announcement)
                    | Transport.requesterId wanted /= Just (Path.via path) ->
                        modifyMVar_
                            (waiting node)
                            (pure . respond now path announcement)
                _ -> pure ()
  where
    destination = DestinationHash (Transport.wantedHash wanted)
    respond now path announcement pending =
        Map.insert
            destination
            (Transport.responding now through path announcement (Map.lookup destination pending))
            pending

requestPath :: Node -> DestinationHash -> IO ()
requestPath node destination = do
    tag <- Entropy.getEntropy Packet.addressLength
    send node (wanting tag)
  where
    wanting tag =
        Packet
            { Packet.contextFlag = False
            , Packet.transportType = Packet.Broadcast
            , Packet.destinationType = Packet.Plain
            , Packet.packetType = Packet.Data
            , Packet.hops = 0
            , Packet.transportId = Nothing
            , Packet.address = Transport.pathRequestAddress
            , Packet.context = Packet.None
            , Packet.payload =
                Transport.pack
                    Transport.PathRequest
                        { Transport.wantedHash = destinationHashBytes destination
                        , Transport.requesterId =
                            if transport (settings node) then Just (ours node) else Nothing
                        , Transport.tag = Just tag
                        }
            }

-- | The two curve scalars are entropy and nothing else.
keypair :: IO Identity.PrivateKey
keypair = do
    bytes <- Entropy.getEntropy Identity.keySize
    either (ioError . userError) pure (Identity.privateKey bytes)

spread :: IO Double
spread = do
    bytes <- Entropy.getEntropy 1
    pure $ case B.unpack bytes of
        [byte] -> Transport.window * fromIntegral byte / 256
        _ -> 0

stampLength :: Int
stampLength = 5

-- | Entropy first, then the unix time it was emitted at.
randomHash :: IO ByteString
randomHash = do
    entropy <- Entropy.getEntropy (Announce.randomHashLength - stampLength)
    now <- getPOSIXTime
    pure (entropy <> stamp (floor now))

stamp :: Word64 -> ByteString
stamp value =
    B.pack [fromIntegral (value `shiftR` (8 * place)) | place <- [stampLength - 1, stampLength - 2 .. 0]]
