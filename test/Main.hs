module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, readMVar)
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Either (rights)
import Data.IORef (atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, isNothing, listToMaybe)
import Data.Word (Word8)
import System.Exit (exitFailure)
import System.IO (BufferMode (LineBuffering), hSetBuffering, stdout)

import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Node as Node
import qualified Reticulum.Packet as Packet
import Reticulum.Path (Time (Time))
import qualified Reticulum.Path as Path
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
    [ ("a path response is not queued", pure notQueued)
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

pathFor :: Word8 -> Path.Table ()
pathFor away =
    Map.singleton
        (Destination.DestinationHash destination)
        Path.Path
            { Path.via = elsewhere
            , Path.hops = away
            , Path.updated = Time 0
            , Path.expires = Time 100
            , Path.blobs = []
            , Path.state = Path.Unknown
            , Path.announced = B.empty
            , Path.interface = ()
            }

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
        case Transport.queued (Time 0) 0 () response of
            Nothing -> True
            Just _ -> False
  where
    response = (announced 1 Nothing) {Packet.context = Packet.PathResponse}

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
        keep onward raw
        readMVar there >>= \at -> Node.inbound right at raw
    back <- Node.interface label $ \raw -> do
        keep backward raw
        readMVar here >>= \at -> Node.inbound left at raw
    putMVar here toward
    putMVar there back
    Node.attach left toward
    Node.attach right back
    pure (readIORef onward, readIORef backward)
  where
    keep into raw = atomicModifyIORef' into (\kept -> (kept ++ [raw], ()))

wire :: String -> Node.Node -> Node.Node -> IO ()
wire label left right = () <$ tap label left right

started :: Bool -> IO (Node.Node, Identity.IdentityHash)
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
                Right node -> pure (node, Identity.identityHash key)

carried :: ByteString
carried = C.pack "test.carried"

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
    (first, emitter) <- started False
    (middle, carrier) <- started True
    (far, _) <- started False
    wire "one" first middle
    wire "two" middle far
    Node.announce first (Destination.name carried) B.empty
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
    (first, emitter) <- started False
    (middle, _) <- started False
    (far, _) <- started False
    wire "one" first middle
    wire "two" middle far
    Node.announce first (Destination.name carried) B.empty
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

throughTheMiddle :: IO (Either String ())
throughTheMiddle = do
    (near, _) <- started False
    (middle, _) <- started True
    (far, emitter) <- started False
    (_, backToNear) <- tap "one" near middle
    (towardFar, _) <- tap "two" middle far
    Node.announce far (Destination.name carried) B.empty
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
