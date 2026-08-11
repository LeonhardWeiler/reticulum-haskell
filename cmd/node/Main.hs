module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, readMVar)
import Control.Exception (IOException, try)
import Control.Monad (forever)
import Data.ByteArray.Encoding (Base (Base16), convertToBase)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import System.Environment (getArgs, getProgName)
import System.Exit (exitFailure)
import System.IO (BufferMode (LineBuffering), hPutStrLn, hSetBuffering, stderr, stdout)

import qualified Reticulum.Announce as Announce
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Interface.Tcp as Tcp
import qualified Reticulum.Node as Node
import qualified Reticulum.Path as Path

main :: IO ()
main = do
    hSetBuffering stdout LineBuffering
    arguments <- getArgs
    case arguments of
        [host, port] -> run host port Nothing Nothing
        [host, port, called] -> run host port (Just (C.pack called)) Nothing
        [host, port, called, file] -> run host port (Just (C.pack called)) (Just file)
        _ -> usage

usage :: IO a
usage = do
    called <- getProgName
    stop (unlines [called ++ " <host> <port> [<destination name> [<identity file>]]"])

run :: String -> String -> Maybe ByteString -> Maybe FilePath -> IO ()
run host port called file = do
    private <- secret file
    key <- either stop pure (Identity.toPublic private)
    putStrLn (unwords ["identity", hex (Identity.identityHashBytes (Identity.identityHash key))])
    started <- Node.start private announced
    node <- either stop pure started
    holder <- newEmptyMVar
    tcp <- Tcp.start (Tcp.Peer host port) (delivered node holder)
    let through = Node.Interface (host ++ ":" ++ port) (Tcp.transmit tcp)
    putMVar holder through
    Node.attach node through
    mapM_ (announcing node) called
    forever (threadDelay (60 * 1000 * 1000))

-- | The interface is what the packet is filed under, so the read
-- thread waits for the interface it is reading for.
delivered :: Node.Node -> MVar Node.Interface -> ByteString -> IO ()
delivered node holder raw = do
    through <- readMVar holder
    Node.inbound node through raw

announcing :: Node.Node -> ByteString -> IO ()
announcing node called = do
    threadDelay (2 * 1000 * 1000)
    Node.announce node (Destination.name called) B.empty

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
secret (Just file) = do
    held <- try (B.readFile file)
    case held :: Either IOException ByteString of
        Right bytes -> either stop pure (Identity.privateKey bytes)
        Left _ -> do
            private <- Node.keypair
            B.writeFile file (Identity.privateKeyBytes private)
            pure private

hex :: ByteString -> String
hex = C.unpack . convertToBase Base16

stop :: String -> IO a
stop reason = hPutStrLn stderr reason >> exitFailure
