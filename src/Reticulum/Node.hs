{-# LANGUAGE StrictData #-}

module Reticulum.Node
    ( Interface (name, transmit)
    , interface
    , Settings (..)
    , Node
    , start
    , stop
    , attach
    , inbound
    , send
    , announce
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
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Link as Link
import Reticulum.Packet (Packet (Packet))
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Path as Path
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

data Node = Node
    { identity :: Identity.PrivateKey
    , ours :: ByteString
    , settings :: Settings
    , attached :: MVar [Interface]
    , table :: MVar (Path.Table Interface)
    , waiting :: MVar (Transport.Waiting Interface)
    , returns :: MVar (Transport.Reverse Interface)
    , links :: MVar (Transport.Links Interface)
    , announces :: MVar (Map DestinationHash Packet)
    , seen :: MVar (Set ByteString)
    , local :: MVar (Set DestinationHash)
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
            Node private (Identity.identityHashBytes (Identity.identityHash key)) how
                <$> newMVar []
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Map.empty
                <*> newMVar Set.empty
                <*> newMVar Set.empty
        let built = node handler Nothing
        if transport how
            then do
                thread <- forkIO (forever (threadDelay sweepInterval >> sweep built))
                pure (Right built {sweeper = Just thread})
            else pure (Right built)

stop :: Node -> IO ()
stop = maybe (pure ()) killThread . sweeper

attach :: Node -> Interface -> IO ()
attach node through = modifyMVar_ (attached node) (pure . (++ [through]))

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
    when allowed $
        if Packet.packetType packet == Packet.Announce
            then announced node through packet
            else forwarding node (relay node through packet)
  where
    filtered crossings hashes
        | not verdict = (hashes, False)
        | Transport.remembered crossings packet =
            (Set.insert (Packet.packetHash packet) hashes, True)
        | otherwise = (hashes, True)
      where
        verdict = Transport.admitted (ours node) hashes packet

announced :: Node -> Interface -> Packet -> IO ()
announced node through packet = case Announce.announce packet of
    Left _ -> pure ()
    Right carried
        | not (Announce.destinationMatch address carried) -> pure ()
        | not (Announce.signatureValid address carried) -> pure ()
        | otherwise -> do
            mine <- readMVar (local node)
            when (destination `Set.notMember` mine) $ do
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
    sending <- modifyMVar (waiting node) (pure . swapped . Transport.due now)
    mapM_ (rebroadcast node) sending
    modifyMVar_ (returns node) (pure . Transport.forgotten now)
    modifyMVar_ (links node) (pure . Transport.aged now)

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

announce :: Node -> Name -> ByteString -> IO ()
announce node called carried = do
    random <- randomHash
    case built random of
        Left reason -> hPutStrLn stderr ("announce for " ++ show (Destination.nameBytes called) ++ ": " ++ reason)
        Right (destination, packet) -> do
            modifyMVar_ (local node) (pure . Set.insert destination)
            send node packet
  where
    hash = Destination.nameHash called
    built random = do
        key <- Identity.toPublic (identity node)
        let destination = Destination.destinationHash hash (Just (Identity.identityHash key))
        body <- Announce.emitted (identity node) destination hash random carried
        pure
            ( destination
            , Packet
                { Packet.contextFlag = False
                , Packet.transportType = Packet.Broadcast
                , Packet.destinationType = Packet.Single
                , Packet.packetType = Packet.Announce
                , Packet.hops = 0
                , Packet.transportId = Nothing
                , Packet.address = destinationHashBytes destination
                , Packet.context = Packet.None
                , Packet.payload = Announce.pack body
                }
            )

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
