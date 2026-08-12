{-# LANGUAGE StrictData #-}

module Reticulum.Node.Transfer
    ( onRequestPacket
    , onAdvertisement
    , askForParts
    , onHashmapUpdate
    , onCancel
    , takePart
    , sendParts
    , hand
    , handOver
    , afterSegment
    ) where

import qualified Codec.Compression.BZip as BZip
import Control.Exception (SomeException, evaluate, try)
import Control.Monad (void, when)
import qualified Crypto.Random.Entropy as Entropy
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as Lazy
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import System.IO (hPutStrLn, stderr)

import qualified Reticulum.Identity as Identity
import Reticulum.Node.State
import Reticulum.Packet (Packet)
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Request as Request
import qualified Reticulum.Resource as Resource
import qualified Reticulum.Link as Link
import qualified Reticulum.Token as Token

onRequestPacket :: Node -> Session -> Packet -> ByteString -> IO ()
onRequestPacket node session packet =
    serveRequest node session (Packet.address packet) (Identity.truncatedHash (Packet.hashablePart packet))

-- | A path this destination does not serve is not answered at all.
serveRequest :: Node -> Session -> ByteString -> ByteString -> ByteString -> IO ()
serveRequest node session link identifier plain = case Request.request plain of
    Left _ -> pure ()
    Right wanted -> case serves =<< Request.pathHash wanted of
        Nothing -> pure ()
        Just handler -> do
            given <- handler (fromMaybe B.empty (Request.requestBody wanted))
            mapM_ (answerRequest node session link identifier) given
  where
    serves path = Map.lookup path (requested (answering session))

-- | An answer that does not fit in one packet on this link is one the
-- far end takes in as a resource, under the id of the request it
-- answers.
answerRequest :: Node -> Session -> ByteString -> ByteString -> ByteString -> IO ()
answerRequest node session link identifier body
    | B.length packed > Link.capacity (unit session) =
        void (handOver node link packed (Just (identifier, True)))
    | otherwise = void (sendSealed node session link Packet.Response packed)
  where
    packed = Request.packResponse identifier body

-- | An advertisement is taken as far as the parts it names, and the
-- first window of them is asked for at once.

onAdvertisement :: Node -> Session -> ByteString -> ByteString -> IO ()
onAdvertisement node session link plain = case Resource.advertisement plain of
    Left _ -> pure ()
    Right told -> case Resource.taking (Link.partSize (unit session)) told of
        Nothing -> pure ()
        Just begun -> do
            onSession node link (keeping begun)
            askForParts node session link (Resource.resource begun)
  where
    keeping begun session' =
        session' {taking = Map.insert (Resource.resource begun) begun (taking session')}

askForParts :: Node -> Session -> ByteString -> ByteString -> IO ()
askForParts node session link wanted = do
    payload <- withSessions node (stepped)
    mapM_ (sendSealed node session link Packet.ResourceReq) payload
  where
    stepped running = case Map.lookup link running >>= (Map.lookup wanted . taking) of
        Nothing -> (running, Nothing)
        Just wanted' -> case Resource.next wanted' of
            Nothing -> (running, Nothing)
            Just (payload, after) -> (Map.adjust (put after) link running, Just payload)
    put after session' = session' {taking = Map.insert wanted after (taking session')}

onHashmapUpdate :: Node -> Session -> ByteString -> ByteString -> IO ()
onHashmapUpdate node session link plain = case Resource.update plain of
    Left _ -> pure ()
    Right told -> do
        onSession node link (learning told)
        askForParts node session link (Resource.updatedResource told)
  where
    learning told session' =
        session' {taking = Map.adjust (Resource.extend told) (Resource.updatedResource told) (taking session')}

onCancel :: Node -> ByteString -> ByteString -> IO ()
onCancel node link plain =
    onSession node link dropping
  where
    dropping session' = session' {taking = Map.delete (Resource.cancel plain) (taking session')}

-- | A part is offered to every resource being taken on the link, and the
-- one whose window holds its hash is the one that keeps it.
takePart :: Node -> Session -> ByteString -> ByteString -> IO ()
takePart node session link raw = do
    moved <- withSessions node (advanced)
    mapM_ (afterPart node session link) moved
  where
    advanced running = case Map.lookup link running of
        Nothing -> (running, [])
        Just session' ->
            let after = Map.map (Resource.part raw) (taking session')
             in (Map.insert link session' {taking = after} running, Map.elems after)

afterPart :: Node -> Session -> ByteString -> Resource.Taking -> IO ()
afterPart node session link taken = case Resource.whole taken of
    Just stream -> assemble node session link taken stream
    Nothing ->
        when (Resource.outstanding taken == 0) (askForParts node session link (Resource.resource taken))

-- | The parts are one token, and what it holds is the random hash the
-- sender put in front and then the data the resource hash covers.
assemble :: Node -> Session -> ByteString -> Resource.Taking -> ByteString -> IO ()
assemble node session link taken stream = do
    whole <- expanded (B.drop Resource.randomHashLength <$> unwrapped)
    forget
    case whole of
        Nothing -> pure ()
        Just body
            | not (Resource.matches taken body) -> pure ()
            | otherwise -> do
                complete <- collectSegment node link taken (Resource.metadata taken body)
                writeOnLink
                    node
                    session
                    (onLink link Packet.Proof Packet.ResourcePrf (Resource.proving body taken))
                mapM_ (deliverWhole node session link taken) complete
  where
    unwrapped
        | Resource.covered taken = Link.opened (keys session) stream
        | otherwise = Just stream
    expanded body
        | Resource.compressed taken = maybe (pure Nothing) expand body
        | otherwise = pure body
    forget = onSession node link dropping
    dropping running = running {taking = Map.delete (Resource.resource taken) (taking running)}

-- | The decompressor throws on bytes that are not what it takes, and
-- nothing that came in over a link is trusted to be them.
expand :: ByteString -> IO (Maybe ByteString)
expand body = do
    outcome <- try (evaluate (Lazy.toStrict (BZip.decompress (Lazy.fromStrict body))))
    pure (either (\reason -> const Nothing (reason :: SomeException)) Just outcome)

-- | A resource in segments is one resource, and only the last of them
-- is answered with what all of them came to; the segment is put away
-- before it is proved, because the next one follows the proof.
collectSegment :: Node -> ByteString -> Resource.Taking -> ByteString -> IO (Maybe ByteString)
collectSegment node link taken body
    | Resource.index taken < Resource.segments taken =
        Nothing <$ onSession node link keeping
    | otherwise = do
        earlier <- withSessions node (gathered)
        pure (Just (earlier <> body))
  where
    keeping running =
        running
            { gathering =
                Map.insertWith (flip (<>)) (Resource.original taken) body (gathering running)
            }
    gathered running = case Map.lookup link running of
        Nothing -> (running, B.empty)
        Just kept ->
            ( Map.insert link kept {gathering = Map.delete (Resource.original taken) (gathering kept)} running
            , fromMaybe B.empty (Map.lookup (Resource.original taken) (gathering kept))
            )

-- | What the whole of a resource was for: the path a request named, the
-- request an answer belongs to, or the end that took it.
deliverWhole :: Node -> Session -> ByteString -> Resource.Taking -> ByteString -> IO ()
deliverWhole node session link taken whole = case Resource.identifier taken of
    Just identifier
        | Resource.asked taken -> serveRequest node session link identifier whole
        | Resource.replied taken -> mapM_ (uncurry (answered (answering session))) back
    _ -> assembled (answering session) whole
  where
    back = case Request.response whole of
        Left _ -> Nothing
        Right taken' -> (,) <$> Request.requestId taken' <*> Request.responseBody taken'

-- | The parts go out as they were cut, because the stream they came
-- from was sealed whole and one of them alone opens nothing.
sendParts :: Node -> Session -> ByteString -> ByteString -> IO ()
sendParts node session link plain = case Resource.partRequest plain of
    Left _ -> pure ()
    Right wanted -> do
        outcome <- withSessions node (stepped wanted)
        case outcome of
            Nothing -> pure ()
            Just (cut, told) -> do
                mapM_ (writeOnLink node session . onLink link Packet.Data Packet.Resource) cut
                mapM_ (void . sendSealed node session link Packet.ResourceHmu . Resource.packUpdate) told
  where
    stepped wanted running = case outgoing running wanted of
        Nothing -> (running, Nothing)
        Just kept ->
            let (cut, told, after) = Resource.handing wanted kept
             in (Map.adjust (put after) link running, Just (cut, told))
    outgoing running wanted =
        Map.lookup link running >>= Map.lookup (Resource.requestedResource wanted) . handing
    put after session' =
        session' {handing = Map.insert (Resource.given after) after (handing session')}

-- | The data is compressed when that is shorter, and what the far end
-- proves is the data and not the stream that carried it.
hand :: Node -> ByteString -> ByteString -> IO (Maybe ByteString)
hand node link body = handOver node link body Nothing

-- | Data longer than one segment goes over a segment at a time, and the
-- hash that comes back is the one the whole of it is known by.
handOver :: Node -> ByteString -> ByteString -> Maybe (ByteString, Bool) -> IO (Maybe ByteString)
handOver node link body asking' = uncurry (advertise node link asking') (Resource.firstSegment body)

advertise
    :: Node
    -> ByteString
    -> Maybe (ByteString, Bool)
    -> ByteString
    -> Resource.Segment
    -> IO (Maybe ByteString)
advertise node link asking' body told = do
    running <- sessions <$> tables node
    case Map.lookup link running of
        Nothing -> pure Nothing
        Just session -> do
            salt <- Entropy.getEntropy Resource.randomHashLength
            vector <- Entropy.getEntropy Token.blockSize
            case Link.sealed (keys session) vector (salt <> carried) of
                Nothing -> Nothing <$ hPutStrLn stderr "resource: nothing was sealed"
                Just stream -> do
                    let kept = made session salt stream
                    onSession node link (keeping kept)
                    _ <- sendSealed node session link Packet.ResourceAdv (advertisement kept)
                    pure (Just (Resource.heading kept))
  where
    (carried, shorter) = Resource.compressing told body
    made session salt stream =
        Resource.giving (Link.partSize (unit session)) told salt body stream shorter asking'
    advertisement = Resource.packAdvertisement . Resource.advertised
    keeping kept session' =
        session' {handing = Map.insert (Resource.given kept) kept (handing session')}

-- | The segment that was proved is followed by the next one, and the
-- end that handed the resource over hears about it once, when the last
-- of them is proved.
afterSegment :: Node -> Session -> ByteString -> Resource.Giving -> IO ()
afterSegment node session link gone = case Resource.nextSegment gone of
    Nothing -> proved (answering session) (Resource.heading gone)
    Just (body, told) -> void (advertise node link (Resource.answers gone) body told)
