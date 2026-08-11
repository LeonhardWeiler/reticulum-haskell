module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, readMVar)
import Control.Exception (IOException, try)
import Control.Monad (forever, void)
import Data.ByteArray.Encoding (Base (Base16), convertFromBase, convertToBase)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.Map.Strict as Map
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Maybe (fromMaybe, isNothing)
import System.Environment (getArgs, getProgName)
import System.Exit (exitFailure)
import System.IO (BufferMode (LineBuffering), hPutStrLn, hSetBuffering, stderr, stdout)

import qualified Reticulum.Announce as Announce
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Interface.Tcp as Tcp
import qualified Reticulum.Node as Node
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Path as Path
import qualified Reticulum.Request as Request

data Options = Options
    { forwarding :: Bool
    , listening :: Maybe String
    , called :: Maybe ByteString
    , dialling :: Maybe ByteString
    , file :: Maybe FilePath
    , peers :: [Tcp.Peer]
    }

main :: IO ()
main = do
    hSetBuffering stdout LineBuffering
    arguments <- getArgs
    case options arguments of
        Left reason -> usage reason
        Right chosen
            | null (peers chosen) && isNothing (listening chosen) ->
                usage "no peer to dial and no port to listen on"
            | otherwise -> run chosen

options :: [String] -> Either String Options
options = go (Options False Nothing Nothing Nothing Nothing [])
  where
    go chosen [] = Right chosen {peers = reverse (peers chosen)}
    go chosen ("-t" : rest) = go chosen {forwarding = True} rest
    go chosen ("-l" : port : rest) = go chosen {listening = Just port} rest
    go chosen ("-n" : name : rest) = go chosen {called = Just (C.pack name)} rest
    go chosen ("-d" : wanted : rest) = case unhex wanted of
        Left reason -> Left reason
        Right bytes -> go chosen {dialling = Just bytes} rest
    go chosen ("-k" : path : rest) = go chosen {file = Just path} rest
    go _ (unknown@('-' : _) : _) = Left ("no such option: " ++ unknown)
    go chosen (address : rest) = case break (== ':') address of
        (host, ':' : port) -> go chosen {peers = Tcp.Peer host port : peers chosen} rest
        _ -> Left ("not a host and a port: " ++ address)

usage :: String -> IO a
usage reason = do
    program <- getProgName
    stop
        ( unlines
            [ reason
            , program ++ " [-t] [-l <port>] [-n <name>] [-d <hex>] [-k <file>] [<host>:<port> ...]"
            ]
        )

run :: Options -> IO ()
run chosen = do
    private <- secret (file chosen)
    key <- either stop pure (Identity.toPublic private)
    putStrLn (unwords ["identity", hex (Identity.identityHashBytes (Identity.identityHash key))])
    started <- Node.start Node.Settings {Node.transport = forwarding chosen} private announced
    node <- either stop pure started
    mapM_ (dialled node) (peers chosen)
    mapM_ (answering node) (listening chosen)
    mapM_ (announcing node) (called chosen)
    mapM_ (talking node) (dialling chosen)
    forever (threadDelay (60 * 1000 * 1000))

dialled :: Node.Node -> Tcp.Peer -> IO ()
dialled node peer = do
    holder <- newEmptyMVar
    tcp <- Tcp.start peer (delivered node holder)
    through <- Node.interface (Tcp.label peer) (Tcp.transmit tcp)
    putMVar holder through
    Node.attach node through

answering :: Node.Node -> String -> IO ()
answering node port = void (Tcp.serve port accepted)
  where
    accepted named connection = do
        holder <- newEmptyMVar
        through <- Node.interface named (Tcp.transmit connection)
        putMVar holder through
        Node.attach node through
        pure (delivered node holder, Node.detach node through)

-- | The interface is what the packet is filed under, so the read
-- thread waits for the interface it is reading for.
delivered :: Node.Node -> MVar Node.Interface -> ByteString -> IO ()
delivered node holder raw = do
    through <- readMVar holder
    Node.inbound node through raw

-- | One path answers with what it was asked and the other with how much
-- that was, so a request too long to answer in one packet has a path.
announcing :: Node.Node -> ByteString -> IO ()
announcing node name = do
    threadDelay (2 * 1000 * 1000)
    destination <- Node.serve node (Destination.name name) B.empty served
    putStrLn (unwords ["serving", hex (Destination.destinationHashBytes destination)])
    Node.announce node destination
  where
    served =
        Node.Answering
            { Node.delivered = \plain -> putStrLn (unwords ["took", show plain])
            , Node.assembled = \plain -> putStrLn (unwords ["assembled", show (B.length plain), "bytes"])
            , Node.requested =
                Map.fromList
                    [ (Request.named (C.pack "echo"), pure . Just)
                    , (Request.named (C.pack "length"), pure . Just . counted)
                    ]
            , Node.proved = const (pure ())
            , Node.answered = \_ _ -> pure ()
            , Node.closed = putStrLn "link closed"
            }
    counted plain = C.pack (show (B.length plain))

-- | A link this node opens, and what it does on it: a packet it has
-- proved, a request, one too long for a packet, and a resource it hands
-- over.
talking :: Node.Node -> ByteString -> IO ()
talking node wanted = do
    named <- newIORef Map.empty
    found <- waitFor (asked node destination)
    case found of
        Nothing -> hPutStrLn stderr "no path to the destination to dial"
        Just _ -> do
            outcome <- Node.open node destination (hears named)
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
                    threadDelay pause
                    Node.close node link
                    putStrLn "closed the link"
  where
    destination = Destination.DestinationHash wanted
    remember named held label =
        mapM_ (\hash -> atomicModifyIORef' named (\kept -> (Map.insert hash label kept, ()))) held

-- | The path is asked for again on every round, because the node the
-- answer has to come through may not be dialled yet.
asked :: Node.Node -> Destination.DestinationHash -> IO (Maybe (Path.Path Node.Interface))
asked node destination = do
    Node.requestPath node destination
    threadDelay (1000 * 1000)
    Map.lookup destination <$> Node.paths node

hears :: IORef (Map.Map ByteString String) -> Node.Answering
hears named =
    Node.Answering
        { Node.delivered = \plain -> putStrLn (unwords ["took", show plain])
        , Node.assembled = \plain -> putStrLn (unwords ["assembled", show (B.length plain), "bytes"])
        , Node.requested = Map.empty
        , Node.proved = \hash -> do
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

announced
    :: Destination.DestinationHash
    -> Announce.Announce
    -> Path.Path Node.Interface
    -> IO ()
announced destination carried path =
    putStrLn $
        unwords
            [ hex (Destination.destinationHashBytes destination)
            , show (Path.hops path)
            , "hops on"
            , Node.name (Path.interface path)
            , show (Announce.appData carried)
            ]

secret :: Maybe FilePath -> IO Identity.PrivateKey
secret Nothing = Node.keypair
secret (Just path) = do
    held <- try (B.readFile path)
    case held :: Either IOException ByteString of
        Right bytes -> either stop pure (Identity.privateKey bytes)
        Left _ -> do
            private <- Node.keypair
            B.writeFile path (Identity.privateKeyBytes private)
            pure private

hex :: ByteString -> String
hex = C.unpack . convertToBase Base16

stop :: String -> IO a
stop reason = hPutStrLn stderr reason >> exitFailure
