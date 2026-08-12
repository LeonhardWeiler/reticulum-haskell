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

import qualified Codec.Compression.BZip as BZip
import Control.Concurrent (ThreadId, forkIO, killThread, threadDelay)
import Control.Concurrent.MVar (MVar, modifyMVar, modifyMVar_, newMVar, readMVar)
import Control.Exception (SomeException, evaluate, try)
import Control.Monad (forever, void, when)
import qualified Crypto.Random.Entropy as Entropy
import Data.Bits (shiftR, testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as Lazy
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Unique (Unique, newUnique)
import Data.Word (Word64, Word8)
import System.IO (hPutStrLn, stderr)

import Reticulum.Announce (Announce)
import qualified Reticulum.Announce as Announce
import qualified Reticulum.Bytes as Bytes
import Reticulum.Destination (DestinationHash (DestinationHash, destinationHashBytes), Name)
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Encryption as Encryption
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Link as Link
import qualified Reticulum.Msgpack as Msgpack
import Reticulum.Packet (Packet (Packet))
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Path as Path
import qualified Reticulum.Request as Request
import qualified Reticulum.Resource as Resource
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
-- it, what it answers on each path it serves, and what it hears about
-- what it sent.
data Answering = Answering
    { delivered :: ByteString -> IO ()
    , assembled :: ByteString -> IO ()
    , requested :: Map ByteString (ByteString -> IO (Maybe ByteString))
    , proved :: ByteString -> IO ()
    , answered :: ByteString -> ByteString -> IO ()
    , closed :: IO ()
    }

data Local = Local
    { nameHash :: Destination.NameHash
    , appData :: ByteString
    , answers :: Answering
    }

-- | A link either end opened: the keys the handshake made, the one
-- interface it is allowed to arrive on, the key the far end signs with,
-- and who it said it is.
data Session = Session
    { keys :: Token.Keys
    , at :: Interface
    , traffic :: Link.Traffic
    , opener :: Bool
    , unit :: Int
    , signer :: ByteString
    , answering :: Answering
    , identified :: Maybe Identity.PublicKey
    , taking :: Map ByteString Resource.Taking
    , handing :: Map ByteString Resource.Giving
    , gathering :: Map ByteString ByteString
    }

-- | A link this node asked for and has no proof of yet: the scalars it
-- offered, the key the answer has to be signed with, and when it went.
data Opening = Opening
    { own :: Identity.PrivateKey
    , theirs :: Identity.PublicKey
    , began :: Path.Time
    , hearing :: Answering
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
    , seen :: MVar Transport.Seen
    , local :: MVar (Map DestinationHash Local)
    , sessions :: MVar (Map ByteString Session)
    , pending :: MVar (Map ByteString Opening)
    , requests :: MVar Transport.Seen
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
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
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
    now <- clock
    allowed <- modifyMVar (seen node) (pure . filtered crossings now)
    when allowed (sorted node through packet)
  where
    filtered crossings now hashes
        | not verdict = (hashes, False)
        | Transport.remembered crossings packet =
            (Map.insert (Packet.packetHash packet) now hashes, True)
        | otherwise = (hashes, True)
      where
        verdict = Transport.admitted (ours node) hashes packet

sorted :: Node -> Interface -> Packet -> IO ()
sorted node through packet
    | Packet.packetType packet == Packet.Announce = announced node through packet
    | Packet.address packet == Transport.pathRequestAddress = asked node through packet
    | otherwise = do
        mine <- readMVar (local node)
        running <- readMVar (sessions node)
        asking' <- readMVar (pending node)
        case Map.lookup (DestinationHash (Packet.address packet)) mine of
            Just held -> arrived node through held packet
            Nothing -> case Map.lookup (Packet.address packet) running of
                Just session -> spoken node through session packet
                Nothing -> case Map.lookup (Packet.address packet) asking' of
                    Just wanted -> proven node through wanted packet
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
            scalar <- Entropy.getEntropy Encryption.ephemeralLength
            now <- clock
            case Link.answered (identity node) scalar link wanted of
                Left reason -> hPutStrLn stderr ("link: " ++ reason)
                Right (shook, body) -> do
                    modifyMVar_ (sessions node) (pure . Map.insert link (begun shook now wanted))
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
            , answering = answers held
            , identified = Nothing
            , taking = Map.empty
            , handing = Map.empty
            , gathering = Map.empty
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
    | otherwise = do
        now <- clock
        modifyMVar_ (sessions node) (pure . Map.adjust (came now) link)
        case Packet.packetType packet of
            Packet.Data -> data'
            Packet.Proof -> proof'
            _ -> pure ()
  where
    link = Packet.address packet
    came now held = held {traffic = (traffic held) {Link.inbound = Path.seconds now}}
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
        Packet.Request -> mapM_ (asking node session packet) (opened (Packet.payload packet))
        Packet.Response -> mapM_ given (opened (Packet.payload packet))
        Packet.ResourceAdv -> mapM_ (advertised node session link) (opened (Packet.payload packet))
        Packet.ResourceReq -> mapM_ (giving node session link) (opened (Packet.payload packet))
        Packet.Resource -> piece node session link (Packet.payload packet)
        Packet.ResourceHmu -> mapM_ (updated node session link) (opened (Packet.payload packet))
        Packet.ResourceIcl -> mapM_ (forgotten node link) (opened (Packet.payload packet))
        _ -> pure ()
    awakening = writing node session (onLink link Packet.Data Packet.Keepalive awake)
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
            done <- modifyMVar (sessions node) (pure . dropping written)
            mapM_ (moving node session link) done
    dropping written running = case Map.lookup link running of
        Just held
            | Just gone <- Map.lookup (Resource.provedResource written) (handing held)
            , Resource.concluded written gone ->
                ( Map.insert link held {handing = Map.delete (Resource.given gone) (handing held)} running
                , Just gone
                )
        _ -> (running, Nothing)
    names plain = case Link.identify plain of
        Just who
            | Link.identifyValid link who ->
                modifyMVar_
                    (sessions node)
                    (pure . Map.adjust (\held -> held {identified = Just (Link.identityPublic who)}) link)
        _ -> pure ()
    closes plain = when (plain == link) (ending node session link)

-- | The one packet on a link that carries no token, and the two bytes
-- that are the whole exchange.
alive :: Word8
alive = 0xff

awake :: ByteString
awake = B.singleton 0xfe

-- | Every packet this end writes on a link is one the far end need not
-- be woken for.
writing :: Node -> Session -> Packet -> IO ()
writing node session packet = do
    transmit (at session) (Packet.pack packet)
    now <- clock
    modifyMVar_ (sessions node) (pure . Map.adjust (wrote now) (Packet.address packet))
  where
    wrote now held = held {traffic = (traffic held) {Link.outbound = Path.seconds now}}

-- | A link that ends is one nothing more crosses, and the end that held
-- it hears so once.
ending :: Node -> Session -> ByteString -> IO ()
ending node session link = do
    was <- modifyMVar (sessions node) (pure . swapped . Map.updateLookupWithKey forget link)
    mapM_ (const (closed (answering session))) was
  where
    forget _ _ = Nothing

-- | The close carries the link id, and the end that writes one keeps
-- nothing of the link and is told nothing it did itself.
close :: Node -> ByteString -> IO ()
close node link = do
    running <- readMVar (sessions node)
    case Map.lookup link running of
        Nothing -> pure ()
        Just session -> do
            _ <- sending node session link Packet.LinkClose link
            modifyMVar_ (sessions node) (pure . Map.delete link)

-- | The request is answered under the id of the packet that asked.
asking :: Node -> Session -> Packet -> ByteString -> IO ()
asking node session packet =
    served node session (Packet.address packet) (Identity.truncatedHash (Packet.hashablePart packet))

-- | A path this destination does not serve is not answered at all.
served :: Node -> Session -> ByteString -> ByteString -> ByteString -> IO ()
served node session link identifier plain = case Request.request plain of
    Left _ -> pure ()
    Right wanted -> case serves =<< Request.pathHash wanted of
        Nothing -> pure ()
        Just handler -> do
            given <- handler (fromMaybe B.empty (Request.requestBody wanted))
            mapM_ (responding node session link identifier) given
  where
    serves path = Map.lookup path (requested (answering session))

-- | An answer that does not fit in one packet on this link is one the
-- far end takes in as a resource, under the id of the request it
-- answers.
responding :: Node -> Session -> ByteString -> ByteString -> ByteString -> IO ()
responding node session link identifier body
    | B.length packed > Link.capacity (unit session) =
        void (handed node link packed (Just (identifier, True)))
    | otherwise = void (sending node session link Packet.Response packed)
  where
    packed = Request.packResponse identifier body

-- | The packet is handed back, because the hash the far end proves is
-- one only the end that sent it can name.
sending :: Node -> Session -> ByteString -> Packet.Context -> ByteString -> IO (Maybe Packet)
sending node session link told plain = do
    vector <- Entropy.getEntropy Token.blockSize
    case Link.sealed (keys session) vector plain of
        Nothing -> Nothing <$ hPutStrLn stderr "link: nothing was sealed"
        Just body -> do
            let packet = onLink link Packet.Data told body
            writing node session packet
            pure (Just packet)

-- | An advertisement is taken as far as the parts it names, and the
-- first window of them is asked for at once.
advertised :: Node -> Session -> ByteString -> ByteString -> IO ()
advertised node session link plain = case Resource.advertisement plain of
    Left _ -> pure ()
    Right told -> case Resource.taking (Link.partSize (unit session)) told of
        Nothing -> pure ()
        Just begun -> do
            modifyMVar_ (sessions node) (pure . Map.adjust (keeping begun) link)
            wanting node session link (Resource.resource begun)
  where
    keeping begun held =
        held {taking = Map.insert (Resource.resource begun) begun (taking held)}

wanting :: Node -> Session -> ByteString -> ByteString -> IO ()
wanting node session link wanted = do
    payload <- modifyMVar (sessions node) (pure . stepped)
    mapM_ (sending node session link Packet.ResourceReq) payload
  where
    stepped running = case Map.lookup link running >>= (Map.lookup wanted . taking) of
        Nothing -> (running, Nothing)
        Just held -> case Resource.next held of
            Nothing -> (running, Nothing)
            Just (payload, after) -> (Map.adjust (put after) link running, Just payload)
    put after held = held {taking = Map.insert wanted after (taking held)}

updated :: Node -> Session -> ByteString -> ByteString -> IO ()
updated node session link plain = case Resource.update plain of
    Left _ -> pure ()
    Right told -> do
        modifyMVar_ (sessions node) (pure . Map.adjust (learning told) link)
        wanting node session link (Resource.updatedResource told)
  where
    learning told held =
        held {taking = Map.adjust (Resource.extend told) (Resource.updatedResource told) (taking held)}

forgotten :: Node -> ByteString -> ByteString -> IO ()
forgotten node link plain =
    modifyMVar_ (sessions node) (pure . Map.adjust dropping link)
  where
    dropping held = held {taking = Map.delete (Resource.cancel plain) (taking held)}

-- | A part is offered to every resource being taken on the link, and the
-- one whose window holds its hash is the one that keeps it.
piece :: Node -> Session -> ByteString -> ByteString -> IO ()
piece node session link raw = do
    moved <- modifyMVar (sessions node) (pure . advanced)
    mapM_ (advancing node session link) moved
  where
    advanced running = case Map.lookup link running of
        Nothing -> (running, [])
        Just held ->
            let after = Map.map (Resource.part raw) (taking held)
             in (Map.insert link held {taking = after} running, Map.elems after)

advancing :: Node -> Session -> ByteString -> Resource.Taking -> IO ()
advancing node session link held = case Resource.whole held of
    Just stream -> assembling node session link held stream
    Nothing ->
        when (Resource.outstanding held == 0) (wanting node session link (Resource.resource held))

-- | The parts are one token, and what it holds is the random hash the
-- sender put in front and then the data the resource hash covers.
assembling :: Node -> Session -> ByteString -> Resource.Taking -> ByteString -> IO ()
assembling node session link held stream = do
    whole <- expanded (B.drop Resource.randomHashLength <$> unwrapped)
    forget
    case whole of
        Nothing -> pure ()
        Just body
            | Identity.fullHash (body <> Resource.entropy held) /= Resource.resource held -> pure ()
            | otherwise -> do
                complete <- collected node link held (metadata held body)
                writing
                    node
                    session
                    (onLink link Packet.Proof Packet.ResourcePrf (Resource.proving body held))
                mapM_ (finished node session link held) complete
  where
    unwrapped
        | Resource.covered held = Link.opened (keys session) stream
        | otherwise = Just stream
    expanded body
        | Resource.compressed held = maybe (pure Nothing) decompressed body
        | otherwise = pure body
    forget = modifyMVar_ (sessions node) (pure . Map.adjust dropping link)
    dropping running = running {taking = Map.delete (Resource.resource held) (taking running)}

-- | The decompressor throws on bytes that are not what it takes, and
-- nothing that came in over a link is trusted to be them.
decompressed :: ByteString -> IO (Maybe ByteString)
decompressed body = do
    outcome <- try (evaluate (Lazy.toStrict (BZip.decompress (Lazy.fromStrict body))))
    pure (either (\reason -> const Nothing (reason :: SomeException)) Just outcome)

-- | Metadata is three bytes of length and then that many bytes, and only
-- the first segment carries it.
metadata :: Resource.Taking -> ByteString -> ByteString
metadata held body
    | Resource.prefixed held && Resource.index held == 1 = B.drop (3 + size) body
    | otherwise = body
  where
    size = fromIntegral (Bytes.bigEndian (B.take 3 body))

-- | A resource in segments is one resource, and only the last of them
-- is answered with what all of them came to; the segment is put away
-- before it is proved, because the next one follows the proof.
collected :: Node -> ByteString -> Resource.Taking -> ByteString -> IO (Maybe ByteString)
collected node link held body
    | Resource.index held < Resource.segments held =
        Nothing <$ modifyMVar_ (sessions node) (pure . Map.adjust keeping link)
    | otherwise = do
        earlier <- modifyMVar (sessions node) (pure . gathered)
        pure (Just (earlier <> body))
  where
    keeping running =
        running
            { gathering =
                Map.insertWith (flip (<>)) (Resource.original held) body (gathering running)
            }
    gathered running = case Map.lookup link running of
        Nothing -> (running, B.empty)
        Just kept ->
            ( Map.insert link kept {gathering = Map.delete (Resource.original held) (gathering kept)} running
            , fromMaybe B.empty (Map.lookup (Resource.original held) (gathering kept))
            )

-- | What the whole of a resource was for: the path a request named, the
-- request an answer belongs to, or the end that took it.
finished :: Node -> Session -> ByteString -> Resource.Taking -> ByteString -> IO ()
finished node session link held whole = case Resource.identifier held of
    Just identifier
        | Resource.asked held -> served node session link identifier whole
        | Resource.replied held -> mapM_ (uncurry (answered (answering session))) back
    _ -> assembled (answering session) whole
  where
    back = case Request.response whole of
        Left _ -> Nothing
        Right taken' -> (,) <$> Request.requestId taken' <*> Request.responseBody taken'

-- | The parts go out as they were cut, because the stream they came
-- from was sealed whole and one of them alone opens nothing.
giving :: Node -> Session -> ByteString -> ByteString -> IO ()
giving node session link plain = case Resource.partRequest plain of
    Left _ -> pure ()
    Right wanted -> do
        outcome <- modifyMVar (sessions node) (pure . stepped wanted)
        case outcome of
            Nothing -> pure ()
            Just (cut, told) -> do
                mapM_ (writing node session . onLink link Packet.Data Packet.Resource) cut
                mapM_ (void . sending node session link Packet.ResourceHmu . Resource.packUpdate) told
  where
    stepped wanted running = case held running wanted of
        Nothing -> (running, Nothing)
        Just kept ->
            let (cut, told, after) = Resource.handing wanted kept
             in (Map.adjust (put after) link running, Just (cut, told))
    held running wanted =
        Map.lookup link running >>= Map.lookup (Resource.requestedResource wanted) . handing
    put after session' =
        session' {handing = Map.insert (Resource.given after) after (handing session')}

-- | The data is compressed when that is shorter, and what the far end
-- proves is the data and not the stream that carried it.
hand :: Node -> ByteString -> ByteString -> IO (Maybe ByteString)
hand node link body = handed node link body Nothing

-- | Data longer than one segment goes over a segment at a time, and the
-- hash that comes back is the one the whole of it is known by.
handed :: Node -> ByteString -> ByteString -> Maybe (ByteString, Bool) -> IO (Maybe ByteString)
handed node link body asking' = uncurry (advertising node link asking') (Resource.firstSegment body)

advertising
    :: Node
    -> ByteString
    -> Maybe (ByteString, Bool)
    -> ByteString
    -> Resource.Segment
    -> IO (Maybe ByteString)
advertising node link asking' body told = do
    running <- readMVar (sessions node)
    case Map.lookup link running of
        Nothing -> pure Nothing
        Just session -> do
            salt <- Entropy.getEntropy Resource.randomHashLength
            vector <- Entropy.getEntropy Token.blockSize
            case Link.sealed (keys session) vector (salt <> carried) of
                Nothing -> Nothing <$ hPutStrLn stderr "resource: nothing was sealed"
                Just stream -> do
                    let kept = made session salt stream
                    modifyMVar_ (sessions node) (pure . Map.adjust (keeping kept) link)
                    _ <- sending node session link Packet.ResourceAdv (advertisement kept)
                    pure (Just (Resource.heading kept))
  where
    squeezing = Resource.spanning told body <= Resource.autoCompressLimit
    packed = Lazy.toStrict (BZip.compress (Lazy.fromStrict body))
    shorter = squeezing && B.length packed < B.length body
    carried = if shorter then packed else body
    made session salt stream =
        Resource.giving (Link.partSize (unit session)) told salt body stream shorter asking'
    advertisement = Resource.packAdvertisement . Resource.advertised
    keeping kept session' =
        session' {handing = Map.insert (Resource.given kept) kept (handing session')}

-- | The segment that was proved is followed by the next one, and the
-- end that handed the resource over hears about it once, when the last
-- of them is proved.
moving :: Node -> Session -> ByteString -> Resource.Giving -> IO ()
moving node session link gone = case Resource.nextSegment gone of
    Nothing -> proved (answering session) (Resource.heading gone)
    Just (body, told) -> void (advertising node link (Resource.answers gone) body told)

-- | A proof on a link carries the hash it proves, which one from a
-- destination does not.
proveOnLink :: Node -> Session -> Packet -> IO ()
proveOnLink node session packet = case Identity.sign (identity node) hash of
    Left reason -> hPutStrLn stderr ("proof: " ++ reason)
    Right signed ->
        writing node session (onLink (Packet.address packet) Packet.Proof Packet.None (hash <> signed))
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
                        modifyMVar_ (seen node) (pure . Map.insert (Packet.packetHash packet) now)
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

-- | An announce is kept for as long as there is a path it was learned
-- from, and every other table here has its own way of running out.
sweep :: Node -> IO ()
sweep node = do
    now <- clock
    interfaces <- readMVar (attached node)
    due <- modifyMVar (waiting node) (pure . swapped . Transport.due now)
    mapM_ (rebroadcast node) due
    modifyMVar_ (returns node) (pure . Transport.forgotten now interfaces)
    modifyMVar_ (links node) (pure . Transport.aged now interfaces)
    modifyMVar_ (seen node) (pure . Transport.recalled now)
    modifyMVar_ (requests node) (pure . Transport.recalled now)
    reachable <- modifyMVar (table node) (pure . twice . Map.filter (not . Path.expired now))
    modifyMVar_ (announces node) (pure . (`Map.intersection` reachable))
    running <- readMVar (sessions node)
    mapM_ (timed node now interfaces) (Map.toList running)
  where
    twice kept = (kept, kept)

-- | The end that opened the link is the end that wakes it, and a link
-- nothing has come in on for two intervals is one either end closes; one
-- whose interface is gone cannot be told about it.
timed :: Node -> Path.Time -> [Interface] -> (ByteString, Session) -> IO ()
timed node now interfaces (link, session)
    | at session `notElem` interfaces = ending node session link
    | Link.stale (Path.seconds now) (traffic session) =
        close node link >> closed (answering session)
    | opener session && Link.waking (Path.seconds now) (traffic session) = waken
    | otherwise = pure ()
  where
    waken = do
        writing node session (onLink link Packet.Data Packet.Keepalive (B.singleton alive))
        modifyMVar_ (sessions node) (pure . Map.adjust woke link)
    woke held = held {traffic = (traffic held) {Link.woken = Path.seconds now}}

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
serve node called carried hears = do
    modifyMVar_ (local node) (pure . Map.insert destination held)
    pure destination
  where
    hash = Destination.nameHash called
    destination = whose node hash
    held = Local {nameHash = hash, appData = carried, answers = hears}

-- | The key the link is asked for is the one the announce for that
-- destination carried, and a destination nothing was heard from cannot
-- be asked at all.
open :: Node -> DestinationHash -> Answering -> IO (Either String ByteString)
open node destination hears = do
    cached <- readMVar (announces node)
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
                    modifyMVar_
                        (pending node)
                        (pure . Map.insert link (Opening secret key now hears))
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
proven :: Node -> Interface -> Opening -> Packet -> IO ()
proven node through wanted packet
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
                    modifyMVar_ (sessions node) (pure . Map.insert link session)
                    modifyMVar_ (pending node) (pure . Map.delete link)
                    void (sending node session link Packet.LinkRtt (roundTrip (elapsed now)))
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
    running <- readMVar (sessions node)
    case Map.lookup link running of
        Nothing -> pure Nothing
        Just session -> fmap Packet.packetHash <$> sending node session link Packet.None plain

-- | The answer names the packet that asked, so what comes back is the
-- id that end will hash out of it.
ask :: Node -> ByteString -> ByteString -> ByteString -> IO (Maybe ByteString)
ask node link path body = do
    running <- readMVar (sessions node)
    now <- clock
    case Map.lookup link running of
        Nothing -> pure Nothing
        Just session ->
            wanting' session (Request.packRequest (Path.seconds now) (Request.named path) body)
  where
    wanting' session packed
        | B.length packed > Link.capacity (unit session) =
            Just identifier <$ handed node link packed (Just (identifier, False))
        | otherwise =
            fmap (Identity.truncatedHash . Packet.hashablePart)
                <$> sending node session link Packet.Request packed
      where
        identifier = Identity.truncatedHash packed

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
            now <- clock
            first <- modifyMVar (requests node) (pure . noted wanted now)
            when first (answer node through wanted)
  where
    noted wanted now tags = case Transport.uniqueTag wanted of
        Nothing -> (tags, False)
        Just unique -> (Map.insert unique now tags, unique `Map.notMember` tags)

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
    respond now path announcement held =
        Map.insert
            destination
            (Transport.responding now through path announcement (Map.lookup destination held))
            held

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
