{-# LANGUAGE StrictData #-}

module Reticulum.Node
    ( Interface (..)
    , Node
    , start
    , attach
    , inbound
    , send
    , announce
    , paths
    , clock
    , keypair
    ) where

import Control.Concurrent.MVar (MVar, modifyMVar, modifyMVar_, newMVar, readMVar)
import Control.Monad (when)
import qualified Crypto.Random.Entropy as Entropy
import Data.Bits (shiftR, testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word64)
import System.IO (hPutStrLn, stderr)

import Reticulum.Announce (Announce)
import qualified Reticulum.Announce as Announce
import Reticulum.Destination (DestinationHash (DestinationHash, destinationHashBytes), Name)
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity
import Reticulum.Packet (Packet (Packet))
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Path as Path
import qualified Reticulum.Transport as Transport

data Interface = Interface
    { name :: String
    , transmit :: ByteString -> IO ()
    }

data Node = Node
    { identity :: Identity.PrivateKey
    , ours :: ByteString
    , attached :: MVar [Interface]
    , table :: MVar (Path.Table Interface)
    , seen :: MVar (Set ByteString)
    , local :: MVar (Set DestinationHash)
    , heard :: DestinationHash -> Announce -> Path.Path Interface -> IO ()
    }

start
    :: Identity.PrivateKey
    -> (DestinationHash -> Announce -> Path.Path Interface -> IO ())
    -> IO (Either String Node)
start private handler = case Identity.toPublic private of
    Left reason -> pure (Left reason)
    Right key -> do
        node <-
            Node private (Identity.identityHashBytes (Identity.identityHash key))
                <$> newMVar []
                <*> newMVar Map.empty
                <*> newMVar Set.empty
                <*> newMVar Set.empty
        pure (Right (node handler))

attach :: Node -> Interface -> IO ()
attach node interface = modifyMVar_ (attached node) (pure . (++ [interface]))

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
    allowed <- modifyMVar (seen node) (pure . filtered)
    when (allowed && Packet.packetType packet == Packet.Announce) (announced node through packet)
  where
    filtered hashes
        | not verdict = (hashes, False)
        | Transport.remembered packet = (Set.insert (Packet.packetHash packet) hashes, True)
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
                learned <- modifyMVar (table node) (pure . took now (entry carried))
                mapM_ (heard node destination carried) learned
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

send :: Node -> Packet -> IO ()
send node packet = do
    known <- readMVar (table node)
    case Transport.outbound known packet of
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
