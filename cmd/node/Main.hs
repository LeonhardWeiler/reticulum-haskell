module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, readMVar)
import Control.Exception (IOException, try)
import Control.Monad (forever, void)
import Data.ByteArray.Encoding (Base (Base16), convertToBase)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
import System.Environment (getArgs, getProgName)
import System.Exit (exitFailure)
import System.IO (BufferMode (LineBuffering), hPutStrLn, hSetBuffering, stderr, stdout)

import qualified Reticulum.Announce as Announce
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Interface.Tcp as Tcp
import qualified Reticulum.Node as Node
import qualified Reticulum.Path as Path
import qualified Reticulum.Request as Request

data Options = Options
    { forwarding :: Bool
    , listening :: Maybe String
    , called :: Maybe ByteString
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
options = go (Options False Nothing Nothing Nothing [])
  where
    go chosen [] = Right chosen {peers = reverse (peers chosen)}
    go chosen ("-t" : rest) = go chosen {forwarding = True} rest
    go chosen ("-l" : port : rest) = go chosen {listening = Just port} rest
    go chosen ("-n" : name : rest) = go chosen {called = Just (C.pack name)} rest
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
            , program ++ " [-t] [-l <port>] [-n <name>] [-k <file>] [<host>:<port> ...]"
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

-- | The one path the node serves answers with what it was asked, so
-- the far end can tell the answer came from the request it sent.
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
            , Node.requested = Map.singleton (Request.named (C.pack "echo")) (pure . Just)
            }

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
