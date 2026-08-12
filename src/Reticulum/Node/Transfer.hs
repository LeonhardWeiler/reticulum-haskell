{-# LANGUAGE StrictData #-}

module Reticulum.Node.Transfer
    ( asking
    , advertised
    , wanting
    , updated
    , forgotten
    , piece
    , giving
    , hand
    , handed
    , moving
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

-- | An advertisement is taken as far as the parts it names, and the
-- first window of them is asked for at once.

advertised :: Node -> Session -> ByteString -> ByteString -> IO ()
advertised node session link plain = case Resource.advertisement plain of
    Left _ -> pure ()
    Right told -> case Resource.taking (Link.partSize (unit session)) told of
        Nothing -> pure ()
        Just begun -> do
            onSessions node (Map.adjust (keeping begun) link)
            wanting node session link (Resource.resource begun)
  where
    keeping begun held =
        held {taking = Map.insert (Resource.resource begun) begun (taking held)}

wanting :: Node -> Session -> ByteString -> ByteString -> IO ()
wanting node session link wanted = do
    payload <- withSessions node (stepped)
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
        onSessions node (Map.adjust (learning told) link)
        wanting node session link (Resource.updatedResource told)
  where
    learning told held =
        held {taking = Map.adjust (Resource.extend told) (Resource.updatedResource told) (taking held)}

forgotten :: Node -> ByteString -> ByteString -> IO ()
forgotten node link plain =
    onSessions node (Map.adjust dropping link)
  where
    dropping held = held {taking = Map.delete (Resource.cancel plain) (taking held)}

-- | A part is offered to every resource being taken on the link, and the
-- one whose window holds its hash is the one that keeps it.
piece :: Node -> Session -> ByteString -> ByteString -> IO ()
piece node session link raw = do
    moved <- withSessions node (advanced)
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
            | not (Resource.matches held body) -> pure ()
            | otherwise -> do
                complete <- collected node link held (Resource.metadata held body)
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
    forget = onSessions node (Map.adjust dropping link)
    dropping running = running {taking = Map.delete (Resource.resource held) (taking running)}

-- | The decompressor throws on bytes that are not what it takes, and
-- nothing that came in over a link is trusted to be them.
decompressed :: ByteString -> IO (Maybe ByteString)
decompressed body = do
    outcome <- try (evaluate (Lazy.toStrict (BZip.decompress (Lazy.fromStrict body))))
    pure (either (\reason -> const Nothing (reason :: SomeException)) Just outcome)

-- | A resource in segments is one resource, and only the last of them
-- is answered with what all of them came to; the segment is put away
-- before it is proved, because the next one follows the proof.
collected :: Node -> ByteString -> Resource.Taking -> ByteString -> IO (Maybe ByteString)
collected node link held body
    | Resource.index held < Resource.segments held =
        Nothing <$ onSessions node (Map.adjust keeping link)
    | otherwise = do
        earlier <- withSessions node (gathered)
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
        outcome <- withSessions node (stepped wanted)
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
                    onSessions node (Map.adjust (keeping kept) link)
                    _ <- sending node session link Packet.ResourceAdv (advertisement kept)
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
moving :: Node -> Session -> ByteString -> Resource.Giving -> IO ()
moving node session link gone = case Resource.nextSegment gone of
    Nothing -> proved (answering session) (Resource.heading gone)
    Just (body, told) -> void (advertising node link (Resource.answers gone) body told)
