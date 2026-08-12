module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, readMVar)
import Data.ByteArray.Encoding (Base (Base16), convertFromBase, convertToBase)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import System.Environment (getArgs, getProgName)
import System.Exit (exitFailure)
import System.IO (BufferMode (LineBuffering), hPutStrLn, hSetBuffering, stderr, stdout)

import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Interface.Tcp as Tcp
import qualified Reticulum.Node as Node
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Path as Path
import qualified Reticulum.Resource as Resource

main :: IO ()
main = do
    hSetBuffering stdout LineBuffering
    arguments <- getArgs
    case arguments of
        (wanted : peers) | not (null peers) -> case (unhex wanted, mapM peer peers) of
            (Right destination, Right dialling) -> run destination dialling
            (Left reason, _) -> usage reason
            (_, Left reason) -> usage reason
        _ -> usage "no destination to dial, or no peer to reach it through"
  where
    peer address = case break (== ':') address of
        (host, ':' : port) -> Right (Tcp.Peer host port)
        _ -> Left ("not a host and a port: " ++ address)

usage :: String -> IO a
usage reason = do
    program <- getProgName
    stop (unlines [reason, program ++ " <hex> <host>:<port> ..."])

run :: ByteString -> [Tcp.Peer] -> IO ()
run wanted peers = do
    private <- Node.keypair
    started <- Node.start Node.Settings {Node.transport = False} private (\_ _ _ -> pure ())
    node <- either stop pure started
    mapM_ (dialled node) peers
    talking node wanted

dialled :: Node.Node -> Tcp.Peer -> IO ()
dialled node peer = do
    holder <- newEmptyMVar
    tcp <- Tcp.start peer (delivered node holder)
    through <- Node.interface (Tcp.label peer) (Tcp.transmit tcp)
    putMVar holder through
    Node.attach node through

-- | The interface is what the packet is filed under, so the read
-- thread waits for the interface it is reading for.
delivered :: Node.Node -> MVar Node.Interface -> ByteString -> IO ()
delivered node holder raw = do
    through <- readMVar holder
    Node.inbound node through raw

-- | A link this node opens, and what it does on it: a packet it has
-- proved, a request, one too long for a packet, and a resource it hands
-- over.
talking :: Node.Node -> ByteString -> IO ()
talking node wanted = do
    named <- newIORef Map.empty
    shown <- newIORef []
    found <- waitFor (asked node destination)
    case found of
        Nothing -> hPutStrLn stderr "no path to the destination to dial"
        Just _ -> do
            outcome <- Node.open node destination (hears named shown)
            case outcome of
                Left reason -> hPutStrLn stderr reason
                Right link -> do
                    putStrLn (unwords ["linked", hex link])
                    said <- waitFor (Node.speak node link (C.pack "over the link"))
                    remember named said "packet"
                    _ <- Node.ask node link (C.pack "echo") (C.pack "say it back")
                    threadDelay pause
                    _ <- Node.ask node link (C.pack "length") (grain 4000)
                    threadDelay pause
                    given <- Node.hand node link (grain 3000)
                    remember named given "resource"
                    _ <- waitFor (awaiting shown given)
                    long <- Node.hand node link (grain (Resource.maxSegmentSize + 1000))
                    remember named long "long resource"
                    _ <- waitFor (awaiting shown long)
                    Node.close node link
                    putStrLn "closed the link"
  where
    destination = Destination.DestinationHash wanted
    remember named held label =
        mapM_ (\hash -> atomicModifyIORef' named (\kept -> (Map.insert hash label kept, ()))) held

-- | The next resource waits for the proof of the one before it, so that
-- the link is not closed under either of them.
awaiting :: IORef [ByteString] -> Maybe ByteString -> IO (Maybe ())
awaiting shown wanted = case wanted of
    Nothing -> pure (Just ())
    Just hash -> do
        held <- readIORef shown
        pure (if hash `elem` held then Just () else Nothing)

-- | The path is asked for again on every round, because the node the
-- answer has to come through may not be dialled yet.
asked :: Node.Node -> Destination.DestinationHash -> IO (Maybe (Path.Path Node.Interface))
asked node destination = do
    Node.requestPath node destination
    threadDelay (1000 * 1000)
    Map.lookup destination <$> Node.paths node

hears :: IORef (Map.Map ByteString String) -> IORef [ByteString] -> Node.Answering
hears named shown =
    Node.silent
        { Node.delivered = \plain -> putStrLn (unwords ["took", show plain])
        , Node.assembled = \plain -> putStrLn (unwords ["assembled", show (B.length plain), "bytes"])
        , Node.proved = \hash -> do
            atomicModifyIORef' shown (\kept -> (hash : kept, ()))
            labels <- readIORef named
            putStrLn (unwords [fromMaybe (hex hash) (Map.lookup hash labels), "proved"])
        , Node.answered = \_ body -> putStrLn (unwords ["answer", show body])
        , Node.closed = putStrLn "link closed"
        }

pause :: Int
pause = 3 * 1000 * 1000

waitFor :: IO (Maybe a) -> IO (Maybe a)
waitFor look = go (60 :: Int)
  where
    go 0 = pure Nothing
    go left = do
        found <- look
        case found of
            Just value -> pure (Just value)
            Nothing -> threadDelay (500 * 1000) >> go (left - 1)

-- | Bytes that do not compress, so what is sent is as long as it says.
grain :: Int -> ByteString
grain size = B.take size (B.concat (take (size `div` Identity.hashLength + 1) grains))
  where
    grains = drop 1 (iterate Identity.fullHash (C.pack "reticulum"))

unhex :: String -> Either String ByteString
unhex text = case convertFromBase Base16 (C.pack text) of
    Left reason -> Left (text ++ ": " ++ reason)
    Right bytes
        | B.length bytes == Packet.addressLength -> Right bytes
        | otherwise -> Left (text ++ ": not a destination hash")

hex :: ByteString -> String
hex = C.unpack . convertToBase Base16

stop :: String -> IO a
stop reason = hPutStrLn stderr reason >> exitFailure
