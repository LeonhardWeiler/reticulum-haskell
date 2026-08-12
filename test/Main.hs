module Main (main) where

import qualified Codec.Compression.BZip as BZip
import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, readMVar)
import Control.Monad (when)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as Lazy
import Data.Either (rights)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust, isNothing, listToMaybe)
import Data.Word (Word8)
import System.Exit (exitFailure)
import System.IO (BufferMode (LineBuffering), hSetBuffering, stdout)

import qualified Reticulum.Destination as Destination
import qualified Reticulum.Encryption as Encryption
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Link as Link
import qualified Reticulum.Msgpack as Msgpack
import qualified Reticulum.Node as Node
import qualified Reticulum.Packet as Packet
import Reticulum.Path (Time (Time))
import qualified Reticulum.Path as Path
import qualified Reticulum.Request as Request
import qualified Reticulum.Resource as Resource
import qualified Reticulum.Token as Token
import qualified Reticulum.Transport as Transport

main :: IO ()
main = do
    hSetBuffering stdout LineBuffering
    outcomes <- mapM measure checks
    let failed = length (filter not outcomes)
    putStrLn (unwords [show (length outcomes - failed), "passed,", show failed, "failed"])
    when (failed > 0) exitFailure

checks :: [(String, IO (Either String ()))]
checks =
    [ ("a token opens what it sealed", pure opensWhatItSealed)
    , ("a sealed token is padded to the block", pure paddedToTheBlock)
    , ("a token whose hmac was altered opens nothing", pure alteredOpensNothing)
    , ("what is sealed for an identity opens with its key", pure sealedForAnIdentity)
    , ("a packet for a destination of this node's own is taken and proved", takenAndProved)
    , ("a packet sealed for another key is not taken", notOpened)
    , ("a link this node answers takes what crosses it and proves it", linkAnswered)
    , ("a link this node opens carries what it says and is proved back", linkOpened)
    , ("a link this end closes is gone at the far end", linkClosed True)
    , ("a link the far end closes is gone here", linkClosed False)
    , ("a keepalive is due when the interval has passed", pure whenWoken)
    , ("a request this node sends is answered under the id it named", requestSent 11)
    , ("a request too long for one packet goes as a resource", requestSent 4000)
    , ("a resource this node hands over arrives whole and is proved", resourceGiven 3000)
    , ("a resource past one hashmap is handed the rest of it", resourceGiven 60000)
    , ("a resource past one segment is handed over as two", resourceGiven (Resource.maxSegmentSize + 1000))
    , ("a request on a link is answered on the path it names", requestAnswered)
    , ("a resource is taken in parts and proved", resourceTaken False)
    , ("a resource that is compressed is taken", resourceTaken True)
    , ("a path response is not queued", pure notQueued)
    , ("an announce goes out twice", pure emptiedTwice)
    , ("a rebroadcast heard once is counted", pure counted)
    , ("a rebroadcast heard twice ends the entry", pure enough)
    , ("an announce carried on ends the entry", pure passedOn)
    , ("a rebroadcast carries this node's transport id", pure carriedId)
    , ("a transport node carries an announce two hops", acrossTwoHops)
    , ("a node without the switch carries nothing", nothingCarried)
    , ("a relayed packet names the next hop", pure relayedOn)
    , ("the last hop drops the transport header", pure lastHop)
    , ("a packet for another node is not relayed", pure notOurs)
    , ("a proof goes back the way the packet came", pure backOut)
    , ("a proof on the wrong interface goes nowhere", pure wrongWay)
    , ("a packet crosses a transport node and its proof returns", throughTheMiddle)
    , ("a link is opened across a transport node", linkThroughTheMiddle)
    , ("an answer is held until what it holds is sent", pure heldBack)
    , ("a transport node answers from the announce it kept", pathAnswered)
    , ("a destination answers for itself", ownPathAnswered)
    , ("a request with no tag is not answered", taglessIgnored)
    , ("the same request twice is answered once", twiceAsked)
    , ("a link request crossing is written down", pure linkKept)
    , ("another packet writes no crossing", pure noCrossing)
    , ("a packet on a link goes to the other side", pure alongTheLink)
    , ("a link proof crosses back", pure proofBack)
    , ("a link proof rewrites the hops it took", pure proofRebalances)
    , ("an unsigned link proof goes nowhere", pure proofUnsigned)
    , ("a link proof from the near side goes nowhere", pure proofSideways)
    , ("an unanswered link request is forgotten", pure linkAged)
    , ("a packet on a crossing link is not remembered", pure linkNotRemembered)
    ]

measure :: (String, IO (Either String ())) -> IO Bool
measure (what, check) = do
    outcome <- check
    case outcome of
        Right () -> putStrLn ("ok    " ++ what) >> pure True
        Left reason -> putStrLn ("fail  " ++ what ++ ": " ++ reason) >> pure False

expect :: (Eq a, Show a) => String -> a -> a -> Either String ()
expect what wanted got
    | wanted == got = Right ()
    | otherwise = Left (what ++ ": wanted " ++ show wanted ++ ", got " ++ show got)

require :: String -> Bool -> Either String ()
require what met = if met then Right () else Left what

vector :: ByteString
vector = B.replicate Token.blockSize 0x0f

sealingKeys :: Token.Keys
sealingKeys = Token.keys (B.replicate Encryption.derivedKeyLength 0x09)

opensWhatItSealed :: Either String ()
opensWhatItSealed = case mapM sealing plaintexts of
    Nothing -> Left "a plaintext was not sealed"
    Just read' -> expect "what came back out" (map Just plaintexts) read'
  where
    plaintexts = [B.empty, C.pack "one packet", B.replicate 16 0x41, B.replicate 400 0x42]
    sealing plain = Token.open sealingKeys <$> Token.seal sealingKeys vector plain

paddedToTheBlock :: Either String ()
paddedToTheBlock =
    expect "the ciphertext lengths" (Just [16, 16, 32]) (mapM sizeOf [0, 15, 16])
  where
    sizeOf size =
        B.length . Token.ciphertext <$> Token.seal sealingKeys vector (B.replicate size 0x41)

alteredOpensNothing :: Either String ()
alteredOpensNothing = case Token.seal sealingKeys vector (C.pack "one packet") of
    Nothing -> Left "the plaintext was not sealed"
    Just made ->
        require "an altered token opened" $
            isNothing (Token.open sealingKeys made {Token.hmac = flipped (Token.hmac made)})
  where
    flipped = B.map (`xor` 0x01)

sealedForAnIdentity :: Either String ()
sealedForAnIdentity = do
    secret <- Identity.privateKey (B.replicate Identity.keySize 0x01)
    key <- Identity.toPublic secret
    let salt = Identity.identityHashBytes (Identity.identityHash key)
    case Encryption.sealed ephemeral (Identity.x25519Public key) salt vector spoken of
        Nothing -> Left "the plaintext was not sealed"
        Just made -> do
            expect
                "what the identity read"
                (Just spoken)
                (Encryption.opened (Identity.x25519Private secret) salt made)
            expect
                "what another salt read"
                Nothing
                (Encryption.opened (Identity.x25519Private secret) elsewhere made)
            carried' <- either (const (Left "the payload did not read back")) Right $
                Encryption.encrypted (Encryption.pack made)
            expect
                "what the payload read back as"
                (Just spoken)
                (Encryption.opened (Identity.x25519Private secret) salt carried')
  where
    ephemeral = B.replicate Encryption.ephemeralLength 0x05

announced :: Word8 -> Maybe ByteString -> Packet.Packet
announced travelled through =
    Packet.Packet
        { Packet.contextFlag = False
        , Packet.transportType =
            maybe Packet.Broadcast (const Packet.Transport) through
        , Packet.destinationType = Packet.Single
        , Packet.packetType = Packet.Announce
        , Packet.hops = travelled
        , Packet.transportId = through
        , Packet.address = destination
        , Packet.context = Packet.None
        , Packet.payload = B.empty
        }

destination :: ByteString
destination = B.replicate Packet.addressLength 0x11

held :: Transport.Waiting ()
held = case Transport.queued (Time 0) 0 () (announced 1 Nothing) of
    Nothing -> Map.empty
    Just entry ->
        Map.singleton
            (Destination.DestinationHash destination)
            entry {Transport.retries = 1, Transport.sendAt = Time 5}

onePath :: i -> Word8 -> Path.Path i
onePath at away =
    Path.Path
        { Path.via = elsewhere
        , Path.hops = away
        , Path.updated = Time 0
        , Path.expires = Time 100
        , Path.blobs = []
        , Path.announced = B.empty
        , Path.interface = at
        }

pathFor :: Word8 -> Path.Table ()
pathFor away = Map.singleton (Destination.DestinationHash destination) (onePath () away)

linkRequest :: Packet.Packet
linkRequest =
    (announced 1 Nothing)
        { Packet.packetType = Packet.LinkRequest
        , Packet.payload = B.replicate Link.publicKeysLength 0x55
        }

crossed :: Transport.Links Char
crossed = Transport.crossing (Time 0) 'b' (onePath 'a' 3) linkRequest Map.empty

onLink :: Word8 -> Packet.Packet
onLink away =
    (announced away Nothing)
        { Packet.packetType = Packet.Data
        , Packet.destinationType = Packet.Link
        , Packet.address = Link.linkId linkRequest
        }

linkKept :: Either String ()
linkKept = expect "the crossings written down" 1 (Map.size crossed)

noCrossing :: Either String ()
noCrossing =
    expect "the crossings written down" 0 $
        Map.size (Transport.crossing (Time 0) 'b' (onePath 'a' 3) (carriedTo ours) Map.empty)

alongTheLink :: Either String ()
alongTheLink = do
    expect "toward the far side" (Just 'a') (way 'b' 1)
    expect "back toward the near side" (Just 'b') (way 'a' 3)
    expect "with the wrong hop count" Nothing (way 'b' 3)
  where
    way through away = fst (Transport.alongLink (Time 1) through (onLink away) crossed)

proofBack :: Either String ()
proofBack = case fst (Transport.proofed (const True) 'a' (linkProof 3) crossed) of
    Nothing -> Left "the proof did not cross back"
    Just done -> do
        expect "the way back" 'b' (Transport.back done)
        expect "the hops rewritten" Nothing (snd <$> Transport.rebalanced done)

proofRebalances :: Either String ()
proofRebalances = case fst (Transport.proofed (const True) 'a' (linkProof 2) crossed) of
    Nothing -> Left "the proof did not cross back"
    Just done -> do
        expect "the hops rewritten" (Just 2) (snd <$> Transport.rebalanced done)
        require "the destination whose path was rewritten" $
            (fst <$> Transport.rebalanced done) == Just (Destination.DestinationHash destination)

proofUnsigned :: Either String ()
proofUnsigned =
    require "an unsigned proof crossed back" $
        isNothing (fst (Transport.proofed (const False) 'a' (linkProof 3) crossed))

proofSideways :: Either String ()
proofSideways =
    require "a proof from the near side crossed back" $
        isNothing (fst (Transport.proofed (const True) 'b' (linkProof 3) crossed))

linkProof :: Word8 -> Packet.Packet
linkProof away =
    (announced away Nothing)
        { Packet.packetType = Packet.Proof
        , Packet.context = Packet.LinkRequestProof
        , Packet.address = Link.linkId linkRequest
        }

linkAged :: Either String ()
linkAged = do
    expect "before the request could be answered" 1 (Map.size (Transport.aged (Time 10) sides crossed))
    expect "after it could not" 0 (Map.size (Transport.aged (Time 19) sides crossed))
    expect "with one side gone" 0 (Map.size (Transport.aged (Time 10) ['a'] answered))
  where
    sides = ['a', 'b']
    answered = snd (Transport.proofed (const True) 'a' (linkProof 3) crossed)

linkNotRemembered :: Either String ()
linkNotRemembered =
    require "a packet on a crossing link was remembered" $
        not (Transport.remembered crossed (onLink 1))

carriedTo :: ByteString -> Packet.Packet
carriedTo hop = (announced 1 (Just hop)) {Packet.packetType = Packet.Data}

proofFor :: Packet.Packet -> Packet.Packet
proofFor sent =
    (announced 0 Nothing)
        { Packet.packetType = Packet.Proof
        , Packet.address = B.take Packet.addressLength (Packet.packetHash sent)
        , Packet.payload = B.replicate 64 0x44
        }

relayedOn :: Either String ()
relayedOn = case Transport.relayed ours (pathFor 2) (carriedTo ours) of
    Nothing -> Left "the packet was not relayed"
    Just (_, onward) -> do
        expect "the next hop" (Just elsewhere) (Packet.transportId onward)
        require "the packet left transport" $
            Packet.transportType onward == Packet.Transport

lastHop :: Either String ()
lastHop = case Transport.relayed ours (pathFor 1) (carriedTo ours) of
    Nothing -> Left "the packet was not relayed"
    Just (_, onward) -> do
        expect "the transport id" Nothing (Packet.transportId onward)
        require "the packet is still in transport" $
            Packet.transportType onward == Packet.Broadcast

notOurs :: Either String ()
notOurs =
    require "a packet naming another node was relayed" $
        isNothing (Transport.relayed ours (pathFor 2) (carriedTo elsewhere))

backOut :: Either String ()
backOut = case Transport.returned 'b' (proofFor sent) kept of
    (Nothing, _) -> Left "the proof found no way back"
    (Just back, rest) -> do
        expect "the way back" 'a' back
        expect "the entries left" 0 (Map.size rest)
  where
    sent = carriedTo ours
    kept = Transport.remember 'a' 'b' (Time 0) sent Map.empty

wrongWay :: Either String ()
wrongWay = case Transport.returned 'a' (proofFor sent) kept of
    (Just _, _) -> Left "the proof came back the way it went out"
    (Nothing, rest) -> expect "the entries left" 0 (Map.size rest)
  where
    sent = carriedTo ours
    kept = Transport.remember 'a' 'b' (Time 0) sent Map.empty

notQueued :: Either String ()
notQueued =
    require "a path response was queued" $
        case Transport.queued (Time 0) 0 () answering of
            Nothing -> True
            Just _ -> False
  where
    answering = (announced 1 Nothing) {Packet.context = Packet.PathResponse}

emptiedTwice :: Either String ()
emptiedTwice = case Transport.queued (Time 0) 0 () (announced 1 Nothing) of
    Nothing -> Left "an announce was not queued"
    Just entry -> do
        let table = Map.singleton (Destination.DestinationHash destination) entry
            (first, afterFirst) = Transport.due (Time 0) table
            (waited, afterWait) = Transport.due (Time 1) afterFirst
            (second, afterSecond) = Transport.due (Time 6) afterWait
            (further, _) = Transport.due (Time 12) afterSecond
        expect "the first sending" 1 (length first)
        expect "inside the grace" 0 (length waited)
        expect "the second sending" 1 (length second)
        expect "after the second" 0 (length further)

counted :: Either String ()
counted = case Map.elems (Transport.overheard (Time 0) (announced 2 (Just elsewhere)) held) of
    [entry] -> expect "the rebroadcasts heard" 1 (Transport.rebroadcasts entry)
    entries -> Left ("the entry was dropped, " ++ show (length entries) ++ " left")

enough :: Either String ()
enough =
    expect "the entries left" 0 (Map.size (Transport.overheard (Time 0) heard once))
  where
    once = Transport.overheard (Time 0) heard held
    heard = announced 2 (Just elsewhere)

passedOn :: Either String ()
passedOn =
    expect "the entries left" 0 (Map.size (Transport.overheard (Time 0) heard held))
  where
    heard = announced 3 (Just elsewhere)

carriedId :: Either String ()
carriedId = case Map.elems held of
    [entry] -> do
        let packet = Transport.rebroadcast ours entry
        expect "the transport id" (Just ours) (Packet.transportId packet)
        expect "the hop count" 1 (Packet.hops packet)
        require "the packet is not in transport" $
            Packet.transportType packet == Packet.Transport
        require "the context is not none" (Packet.context packet == Packet.None)
    _ -> Left "the entry is not there"

ours :: ByteString
ours = B.replicate Packet.addressLength 0x22

elsewhere :: ByteString
elsewhere = B.replicate Packet.addressLength 0x33

-- | What one node writes the other reads, and each side is filed under
-- the interface it arrived on; the two readers are what went each way.
tap :: String -> Node.Node -> Node.Node -> IO (IO [ByteString], IO [ByteString])
tap label left right = do
    onward <- newIORef []
    backward <- newIORef []
    here <- newEmptyMVar
    there <- newEmptyMVar
    toward <- Node.interface label $ \raw -> do
        keeping onward raw
        readMVar there >>= \at -> Node.inbound right at raw
    back <- Node.interface label $ \raw -> do
        keeping backward raw
        readMVar here >>= \at -> Node.inbound left at raw
    putMVar here toward
    putMVar there back
    Node.attach left toward
    Node.attach right back
    pure (readIORef onward, readIORef backward)

wire :: String -> Node.Node -> Node.Node -> IO ()
wire label left right = () <$ tap label left right

started :: Bool -> IO (Node.Node, Identity.PrivateKey, Identity.IdentityHash)
started forwarding = do
    private <- Node.keypair
    case Identity.toPublic private of
        Left reason -> ioError (userError reason)
        Right key -> do
            begun <-
                Node.start
                    Node.Settings {Node.transport = forwarding}
                    private
                    (\_ _ _ -> pure ())
            case begun of
                Left reason -> ioError (userError reason)
                Right node -> pure (node, private, Identity.identityHash key)

carried :: ByteString
carried = C.pack "test.carried"

emitting :: Node.Node -> IO ()
emitting node = holding node Node.silent

holding :: Node.Node -> Node.Answering -> IO ()
holding node hears =
    Node.serve node (Destination.name carried) B.empty hears >>= Node.announce node

keeping :: IORef [a] -> a -> IO ()
keeping into value = atomicModifyIORef' into (\kept -> (kept ++ [value], ()))

gathered :: IORef [a] -> IO [a]
gathered kept = fromMaybe [] <$> waitFor (some <$> readIORef kept)
  where
    some values = if null values then Nothing else Just values

waitFor :: IO (Maybe a) -> IO (Maybe a)
waitFor look = go (60 :: Int)
  where
    go 0 = pure Nothing
    go left = do
        found <- look
        case found of
            Just value -> pure (Just value)
            Nothing -> threadDelay 50000 >> go (left - 1)

reached :: Node.Node -> Identity.IdentityHash -> IO (Maybe (Path.Path Node.Interface))
reached node emitter = Map.lookup wanted <$> Node.paths node
  where
    wanted =
        Destination.destinationHash
            (Destination.nameHash (Destination.name carried))
            (Just emitter)

acrossTwoHops :: IO (Either String ())
acrossTwoHops = do
    (first, _, emitter) <- started False
    (middle, _, carrier) <- started True
    (far, _, _) <- started False
    wire "one" first middle
    wire "two" middle far
    emitting first
    found <- waitFor (reached far emitter)
    Node.stop middle
    pure $ case found of
        Nothing -> Left "the announce did not arrive"
        Just path -> do
            expect "the hops taken" 2 (Path.hops path)
            expect
                "the node it came through"
                (Identity.identityHashBytes carrier)
                (Path.via path)

nothingCarried :: IO (Either String ())
nothingCarried = do
    (first, _, emitter) <- started False
    (middle, _, _) <- started False
    (far, _, _) <- started False
    wire "one" first middle
    wire "two" middle far
    emitting first
    threadDelay (2 * 1000 * 1000)
    found <- reached far emitter
    heard <- reached middle emitter
    pure $ do
        require "the announce was not taken by the node between" $
            case heard of
                Just _ -> True
                Nothing -> False
        require "the announce was carried on" $
            case found of
                Nothing -> True
                Just _ -> False

awaited :: IO [ByteString] -> (Packet.Packet -> Bool) -> IO (Maybe Packet.Packet)
awaited reader wanted = waitFor (found <$> reader)
  where
    found = listToMaybe . filter wanted . rights . map Packet.unpack

addressOf :: Identity.IdentityHash -> ByteString
addressOf emitter =
    Destination.destinationHashBytes
        (Destination.destinationHash (Destination.nameHash (Destination.name carried)) (Just emitter))

message :: ByteString -> Packet.Packet
message address =
    (announced 0 Nothing)
        { Packet.packetType = Packet.Data
        , Packet.address = address
        , Packet.payload = C.pack "one packet"
        }

-- | The ephemeral scalar is a constant here, and the node that opens
-- what it sealed never sees it.
sealedTo :: ByteString -> Identity.PublicKey -> ByteString -> Maybe ByteString
sealedTo salt key plain =
    Encryption.pack
        <$> Encryption.sealed
            (B.replicate Encryption.ephemeralLength 0x05)
            (Identity.x25519Public key)
            salt
            vector
            plain

serving :: Node.Node -> IO (IO [ByteString])
serving node = do
    took <- newIORef []
    _ <- Node.serve node (Destination.name carried) B.empty Node.silent {Node.delivered = keeping took}
    pure (readIORef took)

takenAndProved :: IO (Either String ())
takenAndProved = do
    (near, _, _) <- started False
    (far, secret, emitter) <- started False
    (_, backToNear) <- tap "one" near far
    took <- serving far
    key <- either (ioError . userError) pure (Identity.toPublic secret)
    case sealedTo (Identity.identityHashBytes emitter) key spoken of
        Nothing -> pure (Left "the packet was not sealed")
        Just body -> do
            let sent = (message (addressOf emitter)) {Packet.payload = body}
            Node.send near sent
            back <- awaited backToNear ((== Packet.Proof) . Packet.packetType)
            arrived <- took
            pure $ do
                expect "what the destination took" [spoken] arrived
                case back of
                    Nothing -> Left "no proof came back"
                    Just proof -> do
                        expect
                            "what the proof is addressed to"
                            (B.take Packet.addressLength (Packet.packetHash sent))
                            (Packet.address proof)
                        require "the proof is not signed by the destination" $
                            Identity.validate key (Packet.packetHash sent) (Packet.payload proof)

notOpened :: IO (Either String ())
notOpened = do
    (near, _, _) <- started False
    (far, secret, emitter) <- started False
    (_, backToNear) <- tap "one" near far
    took <- serving far
    key <- either (ioError . userError) pure (Identity.toPublic secret)
    case sealedTo elsewhere key spoken of
        Nothing -> pure (Left "the packet was not sealed")
        Just body -> do
            Node.send near ((message (addressOf emitter)) {Packet.payload = body})
            threadDelay (500 * 1000)
            arrived <- took
            proofs <- counting backToNear ((== Packet.Proof) . Packet.packetType)
            pure $ do
                expect "what the destination took" [] arrived
                expect "the proofs that came back" 0 proofs

spoken :: ByteString
spoken = C.pack "one packet"

overTheLink :: ByteString
overTheLink = C.pack "over the link"

onTheLink :: ByteString -> Packet.Context -> ByteString -> Packet.Packet
onTheLink link told body =
    (announced 0 Nothing)
        { Packet.packetType = Packet.Data
        , Packet.destinationType = Packet.Link
        , Packet.address = link
        , Packet.context = told
        , Packet.payload = body
        }

-- | The far side of the link is a key of this test's own, and what it
-- signs with is never the key the destination signs the proof with.
theOtherEnd :: IO (Identity.PrivateKey, Identity.PublicKey)
theOtherEnd = do
    secret <- either (ioError . userError) pure (Identity.privateKey (B.replicate Identity.keySize 0x07))
    key <- either (ioError . userError) pure (Identity.toPublic secret)
    pure (secret, key)

-- | A link opened against a node that answers one: the id both ends
-- computed, the keys both derived, and the way back from the far side.
data Opened = Opened
    { openedLink :: ByteString
    , openedKeys :: Token.Keys
    , openedNear :: Node.Node
    , openedBack :: IO [ByteString]
    , openedKey :: Identity.PublicKey
    }

linked :: Node.Answering -> IO (Either String Opened)
linked answering = do
    (near, _, _) <- started False
    (far, secret, emitter) <- started False
    (_, backToNear) <- tap "one" near far
    _ <- Node.serve far (Destination.name carried) B.empty answering
    key <- either (ioError . userError) pure (Identity.toPublic secret)
    (initiator, ephemeral) <- theOtherEnd
    let wanting =
            (opening (addressOf emitter))
                { Packet.payload =
                    Identity.x25519Public ephemeral <> Identity.ed25519Public ephemeral
                }
        link = Link.linkId wanting
    Node.send near wanting
    given <- awaited backToNear ((== Packet.LinkRequestProof) . Packet.context)
    pure $ case given >>= (either (const Nothing) Just . Link.requestProof . Packet.payload) of
        Nothing -> Left "the link request was not answered"
        Just body
            | not (Link.signatureValid link (Identity.ed25519Public key) body) ->
                Left "the link proof is not signed by the destination"
            | otherwise ->
                case Link.handshake (Identity.x25519Private initiator) (Link.responderPublic body) link of
                    Nothing -> Left "the handshake made no keys"
                    Just shook -> Right (Opened link (Link.keys shook) near backToNear key)

linkAnswered :: IO (Either String ())
linkAnswered = do
    took <- newIORef []
    begun <- linked Node.silent {Node.delivered = keeping took}
    case begun of
        Left reason -> pure (Left reason)
        Right open -> case Link.sealed (openedKeys open) vector overTheLink of
            Nothing -> pure (Left "nothing was sealed for the link")
            Just sealed -> do
                let link = openedLink open
                    sent = onTheLink link Packet.None sealed
                Node.send (openedNear open) sent
                proved <- awaited (openedBack open) delivery
                Node.send (openedNear open) (onTheLink link Packet.Keepalive (B.singleton 0xff))
                back <- awaited (openedBack open) ((== Packet.Keepalive) . Packet.context)
                arrived <- readIORef took
                pure $ do
                    expect "what crossed the link" [overTheLink] arrived
                    case proved of
                        Nothing -> Left "no proof came back"
                        Just proof -> do
                            let hash = Packet.packetHash sent
                                (carries, signed) = B.splitAt (B.length hash) (Packet.payload proof)
                            expect "the link the proof is on" link (Packet.address proof)
                            expect "the hash the proof carries" hash carries
                            require "the proof is not signed by the destination" $
                                Identity.validate (openedKey open) hash signed
                    case back of
                        Nothing -> Left "the keepalive was not answered"
                        Just awake -> expect "what came back" (B.singleton 0xfe) (Packet.payload awake)
  where
    delivery packet =
        Packet.packetType packet == Packet.Proof && Packet.context packet == Packet.None

-- | A link opened against a node that answers one, both ends this
-- node's own: what crossed it, and the proof that came back for it.
linkOpened :: IO (Either String ())
linkOpened = do
    took <- newIORef []
    (near, emitter) <- twoNodes Node.silent {Node.delivered = keeping took}
    found <- waitFor (reached near emitter)
    case found of
        Nothing -> pure (Left "the announce did not arrive")
        Just _ -> do
            proofs <- newIORef []
            opened <-
                Node.open
                    near
                    (Destination.DestinationHash (addressOf emitter))
                    Node.silent {Node.proved = keeping proofs}
            case opened of
                Left reason -> pure (Left reason)
                Right link -> do
                    sent <- waitFor (Node.speak near link overTheLink)
                    arrived <- gathered took
                    proved <- gathered proofs
                    pure $ do
                        require "the link did not open" (isJust sent)
                        expect "what crossed the link" [overTheLink] arrived
                        expect "the hash the proof named" (maybe [] pure sent) proved

-- | Both ends this node's own: the close one of them writes, the end
-- that hears it, and the link that carries nothing afterwards.
linkClosed :: Bool -> IO (Either String ())
linkClosed byOpener = do
    ends <- newIORef []
    (near, _, _) <- started False
    (far, _, emitter) <- started False
    wire "one" near far
    holding far Node.silent {Node.closed = keeping ends ()}
    found <- waitFor (reached near emitter)
    case found of
        Nothing -> pure (Left "the announce did not arrive")
        Just _ -> do
            here <- newIORef []
            opened <-
                Node.open
                    near
                    (Destination.DestinationHash (addressOf emitter))
                    Node.silent {Node.closed = keeping here ()}
            case opened of
                Left reason -> pure (Left reason)
                Right link -> do
                    sent <- waitFor (Node.speak near link overTheLink)
                    Node.close (if byOpener then near else far) link
                    heard <- gathered (if byOpener then ends else here)
                    after <- Node.speak near link overTheLink
                    pure $ do
                        require "the link did not open" (isJust sent)
                        expect "what the end that did not write it heard" [()] heard
                        require "the link carried a packet after the close" (isNothing after)

-- | The interval gone by in either direction is what makes a keepalive
-- due, and two of them with nothing coming in end the link.
whenWoken :: Either String ()
whenWoken = do
    require "a link just opened is woken" (not (Link.waking now (Link.crossed now)))
    require "the interval passed wakes nothing" (Link.waking later (Link.crossed now))
    require "a keepalive written since is written again" $
        not (Link.waking later (Link.crossed now) {Link.woken = later - 1})
    require "what only went out is counted as something coming in" $
        Link.waking later (Link.crossed now) {Link.outbound = later}
    require "one interval of Node.silent is stale" (not (Link.stale later (Link.crossed now)))
    require "two intervals of Node.silent are not" $
        Link.stale (later + Link.keepaliveInterval) (Link.crossed now)
  where
    now = 1000
    later = now + Link.keepaliveInterval

-- | Both ends this node's own: the request one sends, the path the
-- other serves, and the answer filed under the id of the packet that
-- asked.
requestSent :: Int -> IO (Either String ())
requestSent size = do
    (near, emitter) <- twoNodes Node.silent {Node.requested = Map.singleton path (pure . Just . B.reverse)}
    found <- waitFor (reached near emitter)
    case found of
        Nothing -> pure (Left "the announce did not arrive")
        Just _ -> do
            answers <- newIORef []
            opened <-
                Node.open
                    near
                    (Destination.DestinationHash (addressOf emitter))
                    Node.silent {Node.answered = \named given -> keeping answers (named, given)}
            case opened of
                Left reason -> pure (Left reason)
                Right link -> do
                    sent <- waitFor (Node.ask near link echo body)
                    given <- gathered answers
                    pure $ do
                        require "the request did not go" (isJust sent)
                        expect
                            "the answer and the id it names"
                            [(fromMaybe B.empty sent, B.reverse body)]
                            given
  where
    echo = C.pack "echo"
    path = Request.named echo
    body = grain size

-- | Both ends this node's own: the resource one hands over, the parts
-- the other asks for, and the proof that comes back for the whole.
resourceGiven :: Int -> IO (Either String ())
resourceGiven size = do
    took <- newIORef []
    (near, emitter) <- twoNodes Node.silent {Node.assembled = keeping took}
    found <- waitFor (reached near emitter)
    case found of
        Nothing -> pure (Left "the announce did not arrive")
        Just _ -> do
            proofs <- newIORef []
            opened <-
                Node.open
                    near
                    (Destination.DestinationHash (addressOf emitter))
                    Node.silent {Node.proved = keeping proofs}
            case opened of
                Left reason -> pure (Left reason)
                Right link -> do
                    handed <- waitFor (Node.hand near link body)
                    arrived <- gathered took
                    proved <- gathered proofs
                    pure $ do
                        require "the resource did not go" (isJust handed)
                        expect "how much the far end took" [B.length body] (map B.length arrived)
                        expect "what the far end took" [digest body] (map digest arrived)
                        expect "the resource the proof named" (maybe [] pure handed) proved
  where
    body = grain size

-- | What a resource carries is too long to print, and its hash says the
-- same thing.
digest :: ByteString -> ByteString
digest = Identity.fullHash

-- | Bytes that do not compress, so what is sent is as long as what was
-- asked for.
grain :: Int -> ByteString
grain size = B.take size (B.concat (take (size `div` Identity.hashLength + 1) grains))
  where
    grains = drop 1 (iterate Identity.fullHash (C.pack "the resource this node hands over"))

-- | One node that holds a destination and announces it, and one that
-- has heard it.
twoNodes :: Node.Answering -> IO (Node.Node, Identity.IdentityHash)
twoNodes hears = do
    (near, _, _) <- started False
    (far, _, emitter) <- started False
    wire "one" near far
    holding far hears
    pure (near, emitter)

asked :: ByteString -> ByteString -> ByteString
asked path body =
    Msgpack.pack
        ( Msgpack.Array
            [ Msgpack.Float (B.replicate 8 0)
            , Msgpack.Bytes (Request.named path)
            , Msgpack.Bytes body
            ]
        )

requestAnswered :: IO (Either String ())
requestAnswered = do
    begun <- linked Node.silent {Node.requested = Map.singleton (Request.named echo) (pure . Just . B.reverse)}
    case begun of
        Left reason -> pure (Left reason)
        Right open -> do
            unanswered <- crossing open (asked (C.pack "nothing") spoken)
            answered <- crossing open (asked echo spoken)
            pure $ do
                expect "the answer to a path that is not served" Nothing (snd =<< unanswered)
                case answered of
                    Just (sent, Just plain) -> case Request.response plain of
                        Left _ -> Left "the answer did not read back"
                        Right given -> do
                            expect
                                "the request the answer names"
                                (Just (Identity.truncatedHash (Packet.hashablePart sent)))
                                (Request.requestId given)
                            expect
                                "what the answer carries"
                                (Just (B.reverse spoken))
                                (Request.responseBody given)
                    _ -> Left "the request was not answered"
  where
    echo = C.pack "echo"

chunks :: Int -> ByteString -> [ByteString]
chunks size bytes
    | B.null bytes = []
    | otherwise = B.take size bytes : chunks size (B.drop size bytes)

advertising :: Bool -> ByteString -> ByteString -> ByteString -> [ByteString] -> ByteString
advertising compress hash salt stream pieces =
    Msgpack.pack
        ( Msgpack.Map
            [ (Msgpack.Text (C.pack "t"), Msgpack.Unsigned (fromIntegral (B.length stream)))
            , (Msgpack.Text (C.pack "d"), Msgpack.Unsigned (fromIntegral (B.length stream)))
            , (Msgpack.Text (C.pack "n"), Msgpack.Unsigned (fromIntegral (length pieces)))
            , (Msgpack.Text (C.pack "h"), Msgpack.Bytes hash)
            , (Msgpack.Text (C.pack "r"), Msgpack.Bytes salt)
            , (Msgpack.Text (C.pack "o"), Msgpack.Bytes hash)
            , (Msgpack.Text (C.pack "i"), Msgpack.Unsigned 1)
            , (Msgpack.Text (C.pack "l"), Msgpack.Unsigned 1)
            , (Msgpack.Text (C.pack "f"), Msgpack.Unsigned (if compress then 3 else 1))
            , (Msgpack.Text (C.pack "m"), Msgpack.Bytes (B.concat (map (mapHash salt) pieces)))
            ]
        )

mapHash :: ByteString -> ByteString -> ByteString
mapHash salt piece =
    B.take Resource.mapHashLength (Identity.fullHash (piece <> salt))

-- | The far side of a resource: what it advertised, and the parts it
-- hands over one window of requests at a time.
feeding :: Opened -> ByteString -> [ByteString] -> IO ()
feeding open salt pieces = go 0 (length pieces)
  where
    go _ 0 = pure ()
    go round' left = do
        seen <- nth (openedBack open) ((== Packet.ResourceReq) . Packet.context) round'
        case seen >>= (Link.opened (openedKeys open) . Packet.payload) of
            Nothing -> pure ()
            Just plain -> case Resource.partRequest plain of
                Left _ -> pure ()
                Right wanted -> do
                    let hashes = chunks Resource.mapHashLength (Resource.requestedHashes wanted)
                        sending = [piece | piece <- pieces, mapHash salt piece `elem` hashes]
                    mapM_ (Node.send (openedNear open) . onTheLink (openedLink open) Packet.Resource) sending
                    go (round' + 1) (max 0 (left - length sending))

nth :: IO [ByteString] -> (Packet.Packet -> Bool) -> Int -> IO (Maybe Packet.Packet)
nth reader wanted place = waitFor (found <$> reader)
  where
    found = listToMaybe . drop place . filter wanted . rights . map Packet.unpack

resourceTaken :: Bool -> IO (Either String ())
resourceTaken compress = do
    took <- newIORef []
    begun <- linked Node.silent {Node.assembled = keeping took}
    case begun of
        Left reason -> pure (Left reason)
        Right open -> case Link.sealed (openedKeys open) vector (prefix <> inside) of
            Nothing -> pure (Left "the stream was not sealed")
            Just stream -> do
                let pieces = chunks (Link.partSize 500) stream
                    told = advertising compress hash salt stream pieces
                case Link.sealed (openedKeys open) vector told of
                    Nothing -> pure (Left "the advertisement was not sealed")
                    Just sealed -> do
                        Node.send
                            (openedNear open)
                            (onTheLink (openedLink open) Packet.ResourceAdv sealed)
                        feeding open salt pieces
                        proved <- awaited (openedBack open) ((== Packet.ResourcePrf) . Packet.context)
                        arrived <- readIORef took
                        pure $ do
                            expect "the parts the stream was cut into" (parts compress) (length pieces)
                            expect "what the resource carried" [body] arrived
                            case proved of
                                Nothing -> Left "no resource proof came back"
                                Just proof ->
                                    expect
                                        "what the proof carries"
                                        (hash <> Identity.fullHash (body <> hash))
                                        (Packet.payload proof)
  where
    body = C.pack (concat (replicate 100 "the whole resource, in parts. "))
    inside = if compress then packing body else body
    salt = B.replicate Resource.randomHashLength 0x21
    prefix = B.replicate Resource.randomHashLength 0x22
    hash = Identity.fullHash (body <> salt)
    parts True = 1
    parts False = 7

packing :: ByteString -> ByteString
packing = Lazy.toStrict . BZip.compress . Lazy.fromStrict

crossing :: Opened -> ByteString -> IO (Maybe (Packet.Packet, Maybe ByteString))
crossing open plain = case Link.sealed (openedKeys open) vector plain of
    Nothing -> pure Nothing
    Just sealed -> do
        let sent = onTheLink (openedLink open) Packet.Request sealed
        Node.send (openedNear open) sent
        given <- awaited (openedBack open) ((== Packet.Response) . Packet.context)
        pure (Just (sent, Link.opened (openedKeys open) . Packet.payload =<< given))

throughTheMiddle :: IO (Either String ())
throughTheMiddle = do
    (near, _, _) <- started False
    (middle, _, _) <- started True
    (far, _, emitter) <- started False
    (_, backToNear) <- tap "one" near middle
    (towardFar, _) <- tap "two" middle far
    emitting far
    known <- waitFor (reached near emitter)
    outcome <- case known of
        Nothing -> pure (Left "the path to the far node was not learned")
        Just _ -> do
            Node.send near (message (addressOf emitter))
            passed <- awaited towardFar ((== Packet.Data) . Packet.packetType)
            case passed of
                Nothing -> pure (Left "the packet did not cross the node between")
                Just onward -> do
                    Node.send far (proofFor onward)
                    back <- awaited backToNear ((== Packet.Proof) . Packet.packetType)
                    pure $ do
                        expect "the transport id on the last hop" Nothing (Packet.transportId onward)
                        expect "the hops taken" 1 (Packet.hops onward)
                        expect "what arrived" (C.pack "one packet") (Packet.payload onward)
                        require "the proof did not come back" (isJust back)
    Node.stop middle
    pure outcome

opening :: ByteString -> Packet.Packet
opening address =
    (announced 0 Nothing)
        { Packet.packetType = Packet.LinkRequest
        , Packet.address = address
        , Packet.payload = B.replicate Link.publicKeysLength 0x55
        }

answer :: Identity.PrivateKey -> Packet.Packet -> Either String Packet.Packet
answer secret request = do
    key <- Identity.toPublic secret
    let link = Link.linkId request
        body = Link.RequestProof B.empty (Identity.x25519Public key) Nothing
    signed <- Identity.sign secret (Link.signedData link (Identity.ed25519Public key) body)
    pure
        (announced 0 Nothing)
            { Packet.packetType = Packet.Proof
            , Packet.context = Packet.LinkRequestProof
            , Packet.address = link
            , Packet.payload = Link.packRequestProof body {Link.signature = signed}
            }

speaking :: ByteString -> Packet.Packet
speaking link =
    (announced 0 Nothing)
        { Packet.packetType = Packet.Data
        , Packet.destinationType = Packet.Link
        , Packet.address = link
        , Packet.payload = C.pack "over the link"
        }

linkThroughTheMiddle :: IO (Either String ())
linkThroughTheMiddle = do
    (near, _, _) <- started False
    (middle, _, _) <- started True
    (far, secret, emitter) <- started False
    (_, backToNear) <- tap "one" near middle
    (towardFar, _) <- tap "two" middle far
    emitting far
    learned <- waitFor (reached near emitter)
    outcome <- case learned of
        Nothing -> pure (Left "the path to the far node was not learned")
        Just _ -> do
            Node.send near (opening (addressOf emitter))
            wanted <- awaited towardFar ((== Packet.LinkRequest) . Packet.packetType)
            case wanted of
                Nothing -> pure (Left "the link request did not cross")
                Just request -> case answer secret request of
                    Left reason -> pure (Left ("the proof was not made: " ++ reason))
                    Right proof -> do
                        Node.send far proof
                        crossed' <- awaited backToNear ((== Packet.LinkRequestProof) . Packet.context)
                        Node.send near (speaking (Link.linkId request))
                        carried' <- awaited towardFar ((== Packet.Link) . Packet.destinationType)
                        pure $ do
                            require "the link proof did not cross back" (isJust crossed')
                            require "the link carried nothing" (isJust carried')
    Node.stop middle
    pure outcome

heldBack :: Either String ()
heldBack = case Transport.queued (Time 0) 0 'a' (announced 1 Nothing) of
    Nothing -> Left "an announce was not queued"
    Just entry -> do
        let answering =
                Transport.responding (Time 0) 'c' (onePath 'a' 2) (announced 2 Nothing) (Just entry)
            table = Map.singleton (Destination.DestinationHash destination) answering
            (first, afterFirst) = Transport.due (Time 1) table
            (second, _) = Transport.due (Time 20) afterFirst
        expect "the answer" 1 (length first)
        require "the answer is not a path response" $
            map (Packet.context . Transport.rebroadcast ours) first == [Packet.PathResponse]
        expect "the announce that was held" 1 (length second)
        require "what was held is a path response" $
            map (Packet.context . Transport.rebroadcast ours) second == [Packet.None]

asking :: ByteString -> Maybe ByteString -> Packet.Packet
asking wanted tag =
    (announced 0 Nothing)
        { Packet.packetType = Packet.Data
        , Packet.destinationType = Packet.Plain
        , Packet.address = Transport.pathRequestAddress
        , Packet.payload = Transport.pack (Transport.PathRequest wanted Nothing tag)
        }

response :: Packet.Packet -> Bool
response packet =
    Packet.packetType packet == Packet.Announce
        && Packet.context packet == Packet.PathResponse

counting :: IO [ByteString] -> (Packet.Packet -> Bool) -> IO Int
counting reader wanted = length . filter wanted . rights . map Packet.unpack <$> reader

pathAnswered :: IO (Either String ())
pathAnswered = do
    (middle, _, _) <- started True
    (far, _, emitter) <- started False
    wire "two" middle far
    emitting far
    learned <- waitFor (reached middle emitter)
    outcome <- case learned of
        Nothing -> pure (Left "the node between did not learn the path")
        Just _ -> do
            (near, _, _) <- started False
            (_, backToNear) <- tap "one" near middle
            Node.requestPath near (Destination.DestinationHash (addressOf emitter))
            answered <- awaited backToNear response
            found <- reached near emitter
            pure $ do
                require "no path response came back" (isJust answered)
                require "the answer was not learned" (isJust found)
    Node.stop middle
    pure outcome

ownPathAnswered :: IO (Either String ())
ownPathAnswered = do
    (near, _, _) <- started False
    (far, _, emitter) <- started False
    (_, backToNear) <- tap "one" near far
    emitting far
    Node.send near (asking (addressOf emitter) (Just (B.replicate 16 0x66)))
    answered <- awaited backToNear response
    pure (require "no path response came back" (isJust answered))

taglessIgnored :: IO (Either String ())
taglessIgnored = do
    (near, _, _) <- started False
    (far, _, emitter) <- started False
    (_, backToNear) <- tap "one" near far
    emitting far
    Node.send near (asking (addressOf emitter) Nothing)
    threadDelay (1500 * 1000)
    answers <- counting backToNear response
    pure (expect "the answers to a request with no tag" 0 answers)

twiceAsked :: IO (Either String ())
twiceAsked = do
    (near, _, _) <- started False
    (far, _, emitter) <- started False
    (_, backToNear) <- tap "one" near far
    emitting far
    Node.send near (asking (addressOf emitter) (Just (B.replicate 16 0x77)))
    Node.send near (asking (addressOf emitter) (Just (B.replicate 16 0x77)))
    threadDelay (1500 * 1000)
    answers <- counting backToNear response
    pure (expect "the answers to the same request twice" 1 answers)
