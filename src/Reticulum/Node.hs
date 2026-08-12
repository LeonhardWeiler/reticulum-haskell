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
    , open
    , close
    , speak
    , ask
    , hand
    , announce
    , requestPath
    , paths
    , clock
    , keypair
    ) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.STM (newTVarIO)
import Control.Monad (forever, void, when)
import qualified Crypto.Random.Entropy as Entropy
import Data.Bits (testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word8)
import System.IO (hPutStrLn, stderr)

import Reticulum.Announce (Announce)
import qualified Reticulum.Announce as Announce
import Reticulum.Destination (DestinationHash (DestinationHash, destinationHashBytes), Name)
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Encryption as Encryption
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Link as Link
import qualified Reticulum.Msgpack as Msgpack
import Reticulum.Node.State
import Reticulum.Node.Transfer
    ( onAdvertisement
    , onRequestPacket
    , onCancel
    , sendParts
    , hand
    , handOver
    , afterSegment
    , takePart
    , onHashmapUpdate
    )
import Reticulum.Packet (Packet (Packet))
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Path as Path
import qualified Reticulum.Request as Request
import qualified Reticulum.Resource as Resource
import qualified Reticulum.Transport as Transport

start
    :: Settings
    -> Identity.PrivateKey
    -> (DestinationHash -> Announce -> Path.Path Interface -> IO ())
    -> IO (Either String Node)
start how private handler = case Identity.toPublic private of
    Left reason -> pure (Left reason)
    Right key -> do
        started <- newTVarIO empty
        let built =
                Node
                    { identity = private
                    , public = key
                    , ours = Identity.identityHashBytes (Identity.identityHash key)
                    , settings = how
                    , state = started
                    , heard = handler
                    , sweeper = Nothing
                    }
        thread <- forkIO (forever (threadDelay sweepInterval >> sweep built))
        pure (Right built {sweeper = Just thread})


-- | An interface told no access code drops what carries one.
inbound :: Node -> Interface -> ByteString -> IO ()
inbound node through raw
    | maybe True (\(flags, _) -> testBit flags 7) (B.uncons raw) = pure ()
    | otherwise = case Packet.unpack raw of
        Left _ -> pure ()
        Right packet -> admit node through (Transport.counted packet)

admit :: Node -> Interface -> Packet -> IO ()
admit node through packet = do
    crossings <- links <$> tables node
    now <- clock
    allowed <- change node (\was -> let (kept, out) = filtered crossings now (seen was) in (was {seen = kept}, out))
    when allowed (dispatch node through packet)
  where
    filtered crossings now hashes
        | not verdict = (hashes, False)
        | Transport.remembered crossings packet =
            (Map.insert (Packet.packetHash packet) now hashes, True)
        | otherwise = (hashes, True)
      where
        verdict = Transport.admitted (ours node) hashes packet

dispatch :: Node -> Interface -> Packet -> IO ()
dispatch node through packet
    | Packet.packetType packet == Packet.Announce = onAnnounce node through packet
    | Packet.address packet == Transport.pathRequestAddress = onPathRequest node through packet
    | otherwise = do
        now <- tables node
        case Map.lookup (DestinationHash (Packet.address packet)) (local now) of
            Just mine' -> deliver node through mine' packet
            Nothing -> case Map.lookup (Packet.address packet) (sessions now) of
                Just session -> onLinkPacket node through session packet
                Nothing -> case Map.lookup (Packet.address packet) (pending now) of
                    Just wanted -> linkProved node through wanted packet
                    Nothing -> forwarding node (relay node through packet)

-- | A packet for a destination of this node's own goes no further.
deliver :: Node -> Interface -> Local -> Packet -> IO ()
deliver node through mine packet
    | Packet.packetType packet == Packet.LinkRequest = answerLink node through mine packet
    | Packet.packetType packet /= Packet.Data = pure ()
    | Packet.destinationType packet /= Packet.Single = pure ()
    | otherwise = case unsealed node (Packet.payload packet) of
        Nothing -> pure ()
        Just plain -> do
            delivered (answers mine) plain
            prove node through packet

-- | Only the one mode this end derives keys for is answered.
answerLink :: Node -> Interface -> Local -> Packet -> IO ()
answerLink node through mine packet = case Link.request (Packet.payload packet) of
    Left _ -> pure ()
    Right wanted
        | Link.mode (Link.requestSignalling wanted) /= Link.modeAes256Cbc -> pure ()
        | otherwise -> do
            scalar <- Entropy.getEntropy Encryption.ephemeralLength
            now <- clock
            case Link.answered (identity node) scalar link wanted of
                Left reason -> hPutStrLn stderr ("link: " ++ reason)
                Right (shook, body) -> do
                    onSessions node (Map.insert link (begun shook now wanted))
                    transmit through (Packet.pack (written body))
  where
    link = Link.linkId packet
    begun shook now wanted =
        Session
            { keys = Link.keys shook
            , at = through
            , traffic = Link.crossed (Path.seconds now)
            , opener = False
            , unit = Link.transmissionUnit (Link.requestSignalling wanted)
            , signer = Link.ed25519Public wanted
            , answering = answers mine
            , identified = Nothing
            , taking = Map.empty
            , handing = Map.empty
            , gathering = Map.empty
            }
    written body =
        onLink link Packet.Proof Packet.LinkRequestProof (Link.packRequestProof body)


-- | A link packet that arrives on another interface than the one the
-- link was answered on is not on that link.
onLinkPacket :: Node -> Interface -> Session -> Packet -> IO ()
onLinkPacket node through session packet
    | through /= at session = pure ()
    | otherwise = do
        now <- clock
        onSession node link (came now)
        case Packet.packetType packet of
            Packet.Data -> data'
            Packet.Proof -> proof'
            _ -> pure ()
  where
    link = Packet.address packet
    came now session' = session' {traffic = (traffic session') {Link.inbound = Path.seconds now}}
    opened = Link.opened (keys session)
    proof' = case Packet.context packet of
        Packet.None -> witnessed
        Packet.ResourcePrf -> ended
        _ -> pure ()
    data' = case Packet.context packet of
        Packet.Keepalive -> when (Packet.payload packet == B.singleton alive) awakening
        Packet.None -> mapM_ took (opened (Packet.payload packet))
        Packet.LinkIdentify -> mapM_ names (opened (Packet.payload packet))
        Packet.LinkClose -> mapM_ closes (opened (Packet.payload packet))
        Packet.Request -> mapM_ (onRequestPacket node session packet) (opened (Packet.payload packet))
        Packet.Response -> mapM_ given (opened (Packet.payload packet))
        Packet.ResourceAdv -> mapM_ (onAdvertisement node session link) (opened (Packet.payload packet))
        Packet.ResourceReq -> mapM_ (sendParts node session link) (opened (Packet.payload packet))
        Packet.Resource -> takePart node session link (Packet.payload packet)
        Packet.ResourceHmu -> mapM_ (onHashmapUpdate node session link) (opened (Packet.payload packet))
        Packet.ResourceIcl -> mapM_ (onCancel node link) (opened (Packet.payload packet))
        _ -> pure ()
    awakening = writeOnLink node session (onLink link Packet.Data Packet.Keepalive awake)
    took plain = do
        delivered (answering session) plain
        proveOnLink node session packet
    witnessed = case B.splitAt Identity.hashLength (Packet.payload packet) of
        (hash, signed)
            | B.length signed == Identity.signatureLength
            , Identity.verify (signer session) hash signed ->
                proved (answering session) hash
        _ -> pure ()
    given plain = case Request.response plain of
        Right back
            | Just identifier <- Request.requestId back
            , Just body <- Request.responseBody back ->
                answered (answering session) identifier body
        _ -> pure ()
    ended = case Resource.proof (Packet.payload packet) of
        Left _ -> pure ()
        Right written -> do
            done <- withSessions node (dropping written)
            mapM_ (afterSegment node session link) done
    dropping written running = case Map.lookup link running of
        Just session'
            | Just gone <- Map.lookup (Resource.provedResource written) (handing session')
            , Resource.concluded written gone ->
                ( Map.insert link session' {handing = Map.delete (Resource.given gone) (handing session')} running
                , Just gone
                )
        _ -> (running, Nothing)
    names plain = case Link.identify plain of
        Just who
            | Link.identifyValid link who ->
                onSessions
                    node
                    (Map.adjust (\session' -> session' {identified = Just (Link.identityPublic who)}) link)
        _ -> pure ()
    closes plain = when (plain == link) (endLink node session link)

-- | The one packet on a link that carries no token, and the two bytes
-- that are the whole exchange.
alive :: Word8
alive = 0xff

awake :: ByteString
awake = B.singleton 0xfe


-- | A link that ends is one nothing more crosses, and the end that held
-- it hears so once.
endLink :: Node -> Session -> ByteString -> IO ()
endLink node session link = do
    was <- withSessions node (swapped . Map.updateLookupWithKey forget link)
    mapM_ (const (closed (answering session))) was
  where
    forget _ _ = Nothing

-- | The close carries the link id, and the end that writes one keeps
-- nothing of the link and is told nothing it did itself.
close :: Node -> ByteString -> IO ()
close node link = do
    running <- sessions <$> tables node
    case Map.lookup link running of
        Nothing -> pure ()
        Just session -> do
            _ <- sendSealed node session link Packet.LinkClose link
            onSessions node (Map.delete link)

-- | A proof on a link carries the hash it proves, which one from a
-- destination does not.
proveOnLink :: Node -> Session -> Packet -> IO ()
proveOnLink node session packet = case Identity.sign (identity node) hash of
    Left reason -> hPutStrLn stderr ("proof: " ++ reason)
    Right signed ->
        writeOnLink node session (onLink (Packet.address packet) Packet.Proof Packet.None (hash <> signed))
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

onAnnounce :: Node -> Interface -> Packet -> IO ()
onAnnounce node through packet = case Announce.announce packet of
    Left _ -> pure ()
    Right carried
        | not (Announce.destinationMatch address carried) -> pure ()
        | not (Announce.signatureValid address carried) -> pure ()
        | otherwise -> do
            mine <- local <$> tables node
            when (destination `Map.notMember` mine) $ do
                now <- clock
                forwarding node (alter node (\was -> was {waiting = Transport.overheard now packet (waiting was)}))
                learned <- change node (\was -> let (kept, out) = took now (entry carried) (table was) in (was {table = kept}, out))
                case learned of
                    Nothing -> pure ()
                    Just path -> do
                        alter node (\was -> was {announces = Map.insert destination packet (announces was)})
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

queue :: Node -> Path.Time -> Interface -> Packet -> IO ()
queue node now through packet = do
    across <- spread
    case Transport.queued now across through packet of
        Nothing -> pure ()
        Just entry ->
            alter node $ \was ->
                was {waiting = Map.insert (DestinationHash (Packet.address packet)) entry (waiting was)}

-- | This node was named as the next hop, and where the packet goes
-- after it is the path table's answer; a proof for what it passed on
-- goes back the way that packet came.
relay :: Node -> Interface -> Packet -> IO ()
relay node through packet = do
    reachable <- table <$> tables node
    now <- clock
    case Transport.relayed (ours node) reachable packet of
        Just (path, onward) -> do
            alter node $ \was ->
                was {returns = Transport.remember through (Path.interface path) now packet (returns was)}
            alter node (\was -> was {links = Transport.crossing now through path packet (links was)})
            transmit (Path.interface path) (Packet.pack onward)
        Nothing
            | Packet.context packet == Packet.LinkRequestProof -> relayLinkProof node through packet
            | Packet.packetType packet == Packet.Proof -> do
                back <- change node (\was -> let (out, kept) = Transport.returned through packet (returns was) in (was {returns = kept}, out))
                mapM_ (\out -> transmit out (Packet.pack packet)) back
            | otherwise -> do
                out <- change node (\was -> let (onto, kept) = Transport.alongLink now through packet (links was) in (was {links = kept}, onto))
                case out of
                    Nothing -> pure ()
                    Just onward -> do
                        alter node (\was -> was {seen = Map.insert (Packet.packetHash packet) now (seen was)})
                        transmit onward (Packet.pack packet)

-- | The proof for a link this node is in the middle of is checked with
-- the key the announce for that destination carried.
relayLinkProof :: Node -> Interface -> Packet -> IO ()
relayLinkProof node through packet = do
    cached <- announces <$> tables node
    outcome <-
        change node (\was -> let (out, kept) = Transport.proofed (valid cached) through packet (links was) in (was {links = kept}, out))
    case outcome of
        Nothing -> pure ()
        Just crossed -> do
            mapM_ (shortenPath node) (Transport.rebalanced crossed)
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

shortenPath :: Node -> (DestinationHash, Word8) -> IO ()
shortenPath node (destination, away) =
    alter node (\was -> was {table = Path.shorten away destination (table was)})

sweepInterval :: Int
sweepInterval = 1000 * 1000

-- | An announce is kept for as long as there is a path it was learned
-- from, and every other table here has its own way of running out.
sweep :: Node -> IO ()
sweep node = do
    now <- clock
    interfaces <- attached <$> tables node
    due <- change node (\was -> let (out, kept) = Transport.due now (waiting was) in (was {waiting = kept}, out))
    mapM_ (rebroadcast node) due
    alter node (\was -> was {returns = Transport.forgotten now interfaces (returns was)})
    alter node (\was -> was {links = Transport.aged now interfaces (links was)})
    alter node (\was -> was {seen = Transport.recalled now (seen was)})
    alter node (\was -> was {requests = Transport.recalled now (requests was)})
    reachable <- change node (\was -> let kept = Map.filter (not . Path.expired now) (table was) in (was {table = kept}, kept))
    alter node (\was -> was {announces = (`Map.intersection` reachable) (announces was)})
    running <- sessions <$> tables node
    mapM_ (checkLink node now interfaces) (Map.toList running)

-- | The end that opened the link is the end that wakes it, and a link
-- nothing has come in on for two intervals is one either end closes; one
-- whose interface is gone cannot be told about it.
checkLink :: Node -> Path.Time -> [Interface] -> (ByteString, Session) -> IO ()
checkLink node now interfaces (link, session)
    | at session `notElem` interfaces = endLink node session link
    | Link.stale (Path.seconds now) (traffic session) =
        close node link >> closed (answering session)
    | opener session && Link.waking (Path.seconds now) (traffic session) = waken
    | otherwise = pure ()
  where
    waken = do
        writeOnLink node session (onLink link Packet.Data Packet.Keepalive (B.singleton alive))
        onSession node link woke
    woke session' = session' {traffic = (traffic session') {Link.woken = Path.seconds now}}

-- was heard on.
rebroadcast :: Node -> Transport.Pending Interface -> IO ()
rebroadcast node entry = do
    interfaces <- attached <$> tables node
    mapM_ (\through -> transmit through raw) (targets interfaces)
  where
    raw = Packet.pack (Transport.rebroadcast (ours node) entry)
    targets interfaces = case Transport.toward entry of
        Just one -> [one]
        Nothing -> filter (/= Transport.arrived entry) interfaces

send :: Node -> Packet -> IO ()
send node packet = do
    kept <- tables node
    case Transport.outbound (table kept) packet of
        Transport.Along through outgoing -> transmit through (Packet.pack outgoing)
        Transport.Everywhere outgoing ->
            mapM_ (\through -> transmit through (Packet.pack outgoing)) (attached kept)
        Transport.Nowhere -> pure ()

serve :: Node -> Name -> ByteString -> Answering -> IO DestinationHash
serve node called carried hears = do
    alter node (\was -> was {local = Map.insert destination mine (local was)})
    pure destination
  where
    hash = Destination.nameHash called
    destination = ownDestination node hash
    mine = Local {nameHash = hash, appData = carried, answers = hears}

-- | The key the link is asked for is the one the announce for that
-- destination carried, and a destination nothing was heard from cannot
-- be asked at all.
open :: Node -> DestinationHash -> Answering -> IO (Either String ByteString)
open node destination hears = do
    cached <- announces <$> tables node
    case Map.lookup destination cached >>= carriedKey of
        Nothing -> pure (Left "nothing was heard from that destination")
        Just key -> do
            secret <- keypair
            case Identity.toPublic secret of
                Left reason -> pure (Left reason)
                Right point -> do
                    now <- clock
                    let packet = requesting (destinationHashBytes destination) point
                        link = Link.linkId packet
                    alter node $ \was ->
                        was {pending = Map.insert link (Opening secret key now hears) (pending was)}
                    send node packet
                    pure (Right link)
  where
    carriedKey announcement = case Announce.announce announcement of
        Left _ -> Nothing
        Right carried -> Just (Announce.publicKey carried)

-- | The two points offered are of a keypair made for this link and kept
-- nowhere else.
requesting :: ByteString -> Identity.PublicKey -> Packet
requesting toward point =
    Packet
        { Packet.contextFlag = False
        , Packet.transportType = Packet.Broadcast
        , Packet.destinationType = Packet.Single
        , Packet.packetType = Packet.LinkRequest
        , Packet.hops = 0
        , Packet.transportId = Nothing
        , Packet.address = toward
        , Packet.context = Packet.None
        , Packet.payload =
            Link.packRequest
                Link.Request
                    { Link.x25519Public = Identity.x25519Public point
                    , Link.ed25519Public = Identity.ed25519Public point
                    , Link.requestSignalling = Just (Link.signalling Link.defaultUnit)
                    }
        }

-- | The link is open once the proof is signed by the destination, and
-- the round trip that goes back is what the far end waits for.
linkProved :: Node -> Interface -> Opening -> Packet -> IO ()
linkProved node through wanted packet
    | Packet.packetType packet /= Packet.Proof = pure ()
    | Packet.context packet /= Packet.LinkRequestProof = pure ()
    | otherwise = case Link.requestProof (Packet.payload packet) of
        Left _ -> pure ()
        Right body
            | not (Link.signatureValid link key body) -> pure ()
            | otherwise -> case Link.handshake scalar (Link.responderPublic body) link of
                Nothing -> hPutStrLn stderr "link: the handshake made no keys"
                Just shook -> do
                    now <- clock
                    let session = begun shook now body
                    onSessions node (Map.insert link session)
                    alter node (\was -> was {pending = Map.delete link (pending was)})
                    void (sendSealed node session link Packet.LinkRtt (roundTrip (elapsed now)))
  where
    link = Packet.address packet
    key = Identity.ed25519Public (theirs wanted)
    scalar = Identity.x25519Private (own wanted)
    elapsed now = Path.seconds now - Path.seconds (began wanted)
    begun shook now body =
        Session
            { keys = Link.keys shook
            , at = through
            , traffic = Link.crossed (Path.seconds now)
            , opener = True
            , unit = Link.transmissionUnit (Link.proofSignalling body)
            , signer = key
            , answering = hearing wanted
            , identified = Nothing
            , taking = Map.empty
            , handing = Map.empty
            , gathering = Map.empty
            }

-- | The one packet on a link that carries a number, and the far end
-- calls the link open when it arrives.
roundTrip :: Double -> ByteString
roundTrip = Msgpack.pack . Msgpack.double

-- | The hash goes back because the proof the far end writes names it,
-- and the end that sent the packet is the only one that can.
speak :: Node -> ByteString -> ByteString -> IO (Maybe ByteString)
speak node link plain = do
    running <- sessions <$> tables node
    case Map.lookup link running of
        Nothing -> pure Nothing
        Just session -> fmap Packet.packetHash <$> sendSealed node session link Packet.None plain

-- | The answer names the packet that asked, so what comes back is the
-- id that end will hash out of it.
ask :: Node -> ByteString -> ByteString -> ByteString -> IO (Maybe ByteString)
ask node link path body = do
    running <- sessions <$> tables node
    now <- clock
    case Map.lookup link running of
        Nothing -> pure Nothing
        Just session ->
            wanting' session (Request.packRequest (Path.seconds now) (Request.named path) body)
  where
    wanting' session packed
        | B.length packed > Link.capacity (unit session) =
            Just identifier <$ handOver node link packed (Just (identifier, False))
        | otherwise =
            fmap (Identity.truncatedHash . Packet.hashablePart)
                <$> sendSealed node session link Packet.Request packed
      where
        identifier = Identity.truncatedHash packed

announce :: Node -> DestinationHash -> IO ()
announce node destination = do
    mine <- local <$> tables node
    mapM_ (\one -> emit node one Packet.None Nothing) (Map.lookup destination mine)

ownDestination :: Node -> Destination.NameHash -> DestinationHash
ownDestination node hash =
    Destination.destinationHash hash (Just (Identity.identityHash (public node)))

emit :: Node -> Local -> Packet.Context -> Maybe Interface -> IO ()
emit node mine told toward = do
    random <- randomHash
    case built random of
        Left reason -> hPutStrLn stderr ("announce: " ++ reason)
        Right packet -> case toward of
            Nothing -> send node packet
            Just through -> transmit through (Packet.pack packet)
  where
    hash = nameHash mine
    destination = ownDestination node hash
    built random = do
        body <- Announce.emitted (identity node) destination hash random (appData mine)
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
onPathRequest :: Node -> Interface -> Packet -> IO ()
onPathRequest node through packet = case Transport.pathRequest (Packet.payload packet) of
    Left _ -> pure ()
    Right wanted
        | not (Transport.accepted wanted) -> pure ()
        | otherwise -> do
            now <- clock
            first <- change node (\was -> let (kept, out) = noted wanted now (requests was) in (was {requests = kept}, out))
            when first (answerPath node through wanted)
  where
    noted wanted now tags = case Transport.uniqueTag wanted of
        Nothing -> (tags, False)
        Just unique -> (Map.insert unique now tags, unique `Map.notMember` tags)

-- | A destination of this node's own is announced again; one it only
-- knows a path to is answered with the announce that path was learned
-- from, and never toward the node the path runs through.
answerPath :: Node -> Interface -> Transport.PathRequest -> IO ()
answerPath node through wanted = do
    mine <- local <$> tables node
    case Map.lookup destination mine of
        Just one -> emit node one Packet.PathResponse (Just through)
        Nothing -> forwarding node $ do
            kept <- tables node
            now <- clock
            case (Map.lookup destination (table kept), Map.lookup destination (announces kept)) of
                (Just path, Just announcement)
                    | Transport.requesterId wanted /= Just (Path.via path) ->
                        alter node $ \was ->
                            was {waiting = respond now path announcement (waiting was)}
                _ -> pure ()
  where
    destination = DestinationHash (Transport.wantedHash wanted)
    respond now path announcement waiting' =
        Map.insert
            destination
            (Transport.responding now through path announcement (Map.lookup destination waiting'))
            waiting'

requestPath :: Node -> DestinationHash -> IO ()
requestPath node destination = do
    tag <- Entropy.getEntropy Packet.addressLength
    send node (seeking tag)
  where
    seeking tag =
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
    pure (maybe 0 (Transport.spread . fst) (B.uncons bytes))

randomHash :: IO ByteString
randomHash = do
    entropy <- Entropy.getEntropy Announce.randomHashLength
    now <- getPOSIXTime
    pure (Announce.stamped entropy (floor now))
