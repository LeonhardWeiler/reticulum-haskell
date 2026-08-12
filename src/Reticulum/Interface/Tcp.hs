{-# LANGUAGE StrictData #-}

module Reticulum.Interface.Tcp
    ( Peer (..)
    , label
    , Tcp (..)
    , start
    , serve
    ) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (MVar, modifyMVar_, newMVar, withMVar)
import Control.Exception (IOException, bracketOnError, catch, try)
import Control.Monad (forever, unless, void)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Network.Socket as Net
import Network.Socket
    ( AddrInfo (addrAddress, addrFamily, addrFlags, addrSocketType)
    , AddrInfoFlag (AI_PASSIVE)
    , HostName
    , ServiceName
    , ShutdownCmd (ShutdownBoth)
    , Socket
    , SocketOption (KeepAlive, NoDelay, ReuseAddr)
    , SocketType (Stream)
    , close
    , connect
    , defaultHints
    , defaultProtocol
    , getAddrInfo
    , setSocketOption
    , shutdown
    , socket
    )
import qualified Network.Socket.ByteString as Socket
import System.IO (hPutStrLn, stderr)
import System.Timeout (timeout)

import qualified Reticulum.Interface.Hdlc as Hdlc
import Reticulum.Packet (HeaderType (Header1), headerLength)

hardwareMtu :: Int
hardwareMtu = 262144

connectTimeout :: Int
connectTimeout = 5 * 1000000

reconnectWait :: Int
reconnectWait = 5 * 1000000

data Peer = Peer
    { host :: HostName
    , port :: ServiceName
    }

label :: Peer -> String
label peer = host peer ++ ":" ++ port peer

newtype Tcp = Tcp
    { transmit :: ByteString -> IO ()
    }

-- | The socket is dialled, read and dialled again by the one thread,
-- and the interface is what another thread may do to it.
start :: Peer -> (ByteString -> IO ()) -> IO Tcp
start peer deliver = do
    held <- newMVar Nothing
    _ <- forkIO (forever (dialling peer held deliver))
    pure Tcp {transmit = writing (label peer) held . Hdlc.framed}

dialling :: Peer -> MVar (Maybe Socket) -> (ByteString -> IO ()) -> IO ()
dialling peer held deliver = do
    dialled <- try (dial peer)
    case dialled of
        Left failure -> note (label peer) ("no connection: " ++ show (failure :: IOException))
        Right established -> do
            modifyMVar_ held (const (pure (Just established)))
            outcome <- try (reading established deliver)
            modifyMVar_ held (const (pure Nothing))
            quiet (close established)
            note (label peer) (ending outcome)
    threadDelay reconnectWait

dial :: Peer -> IO Socket
dial peer = do
    addresses <- getAddrInfo (Just defaultHints {addrSocketType = Stream}) (Just (host peer)) (Just (port peer))
    case addresses of
        [] -> ioError (userError "no address")
        (address : _) -> bracketOnError (open address) close (settle address)
  where
    open address = socket (addrFamily address) Stream defaultProtocol
    settle address opened = do
        setSocketOption opened NoDelay 1
        setSocketOption opened KeepAlive 1
        reached <- timeout connectTimeout (connect opened (addrAddress address))
        case reached of
            Nothing -> ioError (userError "connection timed out")
            Just () -> pure opened

-- | A frame no longer than a header holds no packet, and one longer
-- than the interface can carry was never sent by a peer of it.
reading :: Socket -> (ByteString -> IO ()) -> IO ()
reading established deliver = go B.empty
  where
    go buffer = do
        chunk <- Socket.recv established 4096
        unless (B.null chunk) $ do
            let (complete, kept) = Hdlc.frames (2 * hardwareMtu) (buffer <> chunk)
            mapM_ deliver (filter carried complete)
            go kept

    carried frame =
        B.length frame > headerLength Header1 && B.length frame <= hardwareMtu

writing :: String -> MVar (Maybe Socket) -> ByteString -> IO ()
writing named held raw = withMVar held sending
  where
    sending Nothing = pure ()
    sending (Just established) =
        Socket.sendAll established raw `catch` \failure -> do
            note named ("transmit failed: " ++ show (failure :: IOException))
            quiet (shutdown established ShutdownBoth)

ending :: Either IOException () -> String
ending (Left failure) = "socket failed: " ++ show failure
ending (Right ()) = "socket closed"

quiet :: IO () -> IO ()
quiet action = void (try action :: IO (Either IOException ()))

note :: String -> String -> IO ()
note named message = hPutStrLn stderr (concat ["tcp ", named, ": ", message])

-- | Every connection accepted is its own interface, and the caller says
-- what reads it and what to do when it ends before the first byte
-- arrives.
serve :: ServiceName -> (String -> Tcp -> IO (ByteString -> IO (), IO ())) -> IO ()
serve service accepted = do
    listening <- bound service
    void (forkIO (forever (taking listening)))
  where
    taking listening = do
        (established, address) <- Net.accept listening
        void (forkIO (served established (show address)))

    served established named = do
        setSocketOption established NoDelay 1
        setSocketOption established KeepAlive 1
        held <- newMVar (Just established)
        (deliver, ended) <-
            accepted named Tcp {transmit = writing named held . Hdlc.framed}
        outcome <- try (reading established deliver)
        modifyMVar_ held (const (pure Nothing))
        quiet (close established)
        note named (ending outcome)
        ended

bound :: ServiceName -> IO Socket
bound service = do
    addresses <-
        getAddrInfo
            (Just defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Stream})
            Nothing
            (Just service)
    case addresses of
        [] -> ioError (userError "no address")
        (address : _) -> bracketOnError (open address) close (settle address)
  where
    open address = socket (addrFamily address) Stream defaultProtocol
    settle address listening = do
        setSocketOption listening ReuseAddr 1
        Net.bind listening (addrAddress address)
        Net.listen listening 8
        pure listening
