{-# LANGUAGE StrictData #-}

module Reticulum.Node.State
    ( Interface (name, transmit)
    , interface
    , Settings (..)
    , Answering (..)
    , silent
    , Local (..)
    , Session (..)
    , Opening (..)
    , State (..)
    , Node (..)
    , empty
    , tables
    , alter
    , change
    , onSessions
    , onSession
    , withSessions
    , stop
    , attach
    , detach
    , paths
    , clock
    , forwarding
    , onLink
    , writeOnLink
    , sendSealed
    , swapped
    ) where

import Control.Concurrent (ThreadId, killThread)
import Control.Concurrent.STM
    ( TVar
    , atomically
    , modifyTVar'
    , readTVar
    , readTVarIO
    , writeTVar
    )
import Control.Monad (when)
import qualified Crypto.Random.Entropy as Entropy
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Unique (Unique, newUnique)
import System.IO (hPutStrLn, stderr)

import Reticulum.Announce (Announce)
import Reticulum.Destination (DestinationHash)
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Link as Link
import Reticulum.Packet (Packet (Packet))
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Path as Path
import qualified Reticulum.Resource as Resource
import qualified Reticulum.Token as Token
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

-- | What a destination of this node's own does with what arrives for
-- it, what it answers on each path it serves, and what it hears about
-- what it sent.
data Answering = Answering
    { delivered :: ByteString -> IO ()
    , assembled :: ByteString -> IO ()
    , requested :: Map ByteString (ByteString -> IO (Maybe ByteString))
    , proved :: ByteString -> IO ()
    , answered :: ByteString -> ByteString -> IO ()
    , closed :: IO ()
    }

silent :: Answering
silent =
    Answering
        { delivered = const (pure ())
        , assembled = const (pure ())
        , requested = Map.empty
        , proved = const (pure ())
        , answered = \_ _ -> pure ()
        , closed = pure ()
        }

data Local = Local
    { nameHash :: Destination.NameHash
    , appData :: ByteString
    , answers :: Answering
    }

-- | A link either end opened: the keys the handshake made, the one
-- interface it is allowed to arrive on, the key the far end signs with,
-- and who it said it is.
data Session = Session
    { keys :: Token.Keys
    , at :: Interface
    , traffic :: Link.Traffic
    , opener :: Bool
    , unit :: Int
    , signer :: ByteString
    , answering :: Answering
    , identified :: Maybe Identity.PublicKey
    , taking :: Map ByteString Resource.Taking
    , handing :: Map ByteString Resource.Giving
    , gathering :: Map ByteString ByteString
    }

-- | A link this node asked for and has no proof of yet: the scalars it
-- offered, the key the answer has to be signed with, and when it went.
data Opening = Opening
    { own :: Identity.PrivateKey
    , theirs :: Identity.PublicKey
    , began :: Path.Time
    , hearing :: Answering
    }

-- | Every table the node keeps, so that what reads two of them reads
-- them as they stood at one moment.
data State = State
    { attached :: [Interface]
    , table :: Path.Table Interface
    , waiting :: Transport.Waiting Interface
    , returns :: Transport.Reverse Interface
    , links :: Transport.Links Interface
    , announces :: Map DestinationHash Packet
    , seen :: Transport.Seen
    , local :: Map DestinationHash Local
    , sessions :: Map ByteString Session
    , pending :: Map ByteString Opening
    , requests :: Transport.Seen
    }

data Node = Node
    { identity :: Identity.PrivateKey
    , public :: Identity.PublicKey
    , ours :: ByteString
    , settings :: Settings
    , state :: TVar State
    , heard :: DestinationHash -> Announce -> Path.Path Interface -> IO ()
    , sweeper :: Maybe ThreadId
    }

empty :: State
empty =
    State
        { attached = []
        , table = Map.empty
        , waiting = Map.empty
        , returns = Map.empty
        , links = Map.empty
        , announces = Map.empty
        , seen = Map.empty
        , local = Map.empty
        , sessions = Map.empty
        , pending = Map.empty
        , requests = Map.empty
        }

tables :: Node -> IO State
tables = readTVarIO . state

alter :: Node -> (State -> State) -> IO ()
alter node step = atomically (modifyTVar' (state node) step)

change :: Node -> (State -> (State, a)) -> IO a
change node step = atomically $ do
    was <- readTVar (state node)
    let (now, out) = step was
    writeTVar (state node) now
    pure out

onSessions :: Node -> (Map ByteString Session -> Map ByteString Session) -> IO ()
onSessions node step = alter node (\was -> was {sessions = step (sessions was)})

onSession :: Node -> ByteString -> (Session -> Session) -> IO ()
onSession node link step = onSessions node (Map.adjust step link)

withSessions :: Node -> (Map ByteString Session -> (Map ByteString Session, a)) -> IO a
withSessions node step =
    change node (\was -> let (now, out) = step (sessions was) in (was {sessions = now}, out))

stop :: Node -> IO ()
stop = maybe (pure ()) killThread . sweeper

attach :: Node -> Interface -> IO ()
attach node through = alter node (\was -> was {attached = attached was ++ [through]})

detach :: Node -> Interface -> IO ()
detach node through = alter node (\was -> was {attached = filter (/= through) (attached was)})

paths :: Node -> IO (Path.Table Interface)
paths = fmap table . tables

clock :: IO Path.Time
clock = Path.Time . realToFrac <$> getPOSIXTime

forwarding :: Node -> IO () -> IO ()
forwarding node action = when (transport (settings node)) action

onLink :: ByteString -> Packet.PacketType -> Packet.Context -> ByteString -> Packet
onLink link kind told body =
    Packet
        { Packet.contextFlag = False
        , Packet.transportType = Packet.Broadcast
        , Packet.destinationType = Packet.Link
        , Packet.packetType = kind
        , Packet.hops = 0
        , Packet.transportId = Nothing
        , Packet.address = link
        , Packet.context = told
        , Packet.payload = body
        }

-- | Every packet this end writes on a link is one the far end need not
-- be woken for.
writeOnLink :: Node -> Session -> Packet -> IO ()
writeOnLink node session packet = do
    transmit (at session) (Packet.pack packet)
    now <- clock
    onSession node (Packet.address packet) (wrote now)
  where
    wrote now session' = session' {traffic = (traffic session') {Link.outbound = Path.seconds now}}

-- | The packet is handed back: the hash the far end proves is one only
-- the end that sent it can name.
sendSealed :: Node -> Session -> ByteString -> Packet.Context -> ByteString -> IO (Maybe Packet)
sendSealed node session link told plain = do
    vector <- Entropy.getEntropy Token.blockSize
    case Link.sealed (keys session) vector plain of
        Nothing -> Nothing <$ hPutStrLn stderr "link: nothing was sealed"
        Just body -> do
            let packet = onLink link Packet.Data told body
            writeOnLink node session packet
            pure (Just packet)

swapped :: (a, b) -> (b, a)
swapped (one, other) = (other, one)
