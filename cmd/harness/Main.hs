-- | The corpus's cmd/dump, over this implementation. The contract is
-- corpus doc/harness; the six rules it names are cited by number below.
module Main (main) where

import qualified Data.ByteArray.Encoding as Encoding
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Word (Word8)
import System.Environment (getArgs, getProgName)
import System.Exit (ExitCode (ExitFailure), die, exitWith)

import qualified Reticulum.Announce as Announce
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Transport as Transport

main :: IO ()
main = do
    args <- getArgs
    case args of
        [kind, path] -> do
            blobs <- readBlobs path
            case dump kind blobs of
                -- Rule 3. Nothing else may use this status.
                Nothing -> exitWith (ExitFailure 77)
                Just (Left reason) -> die (path ++ ": " ++ reason)
                Just (Right fields) -> mapM_ (putStrLn . render) fields
        ("-e" : _) -> die "the encode direction is not implemented"
        _ -> do
            name <- getProgName
            die ("usage: " ++ name ++ " <kind> <rawfile>")

-- | Nothing for a kind this harness does not implement, Left for a raw
-- that does not carry what the kind is defined to hold. The second is a
-- broken vector, not a measurement.
dump :: String -> [Maybe ByteString] -> Maybe (Either String [Field])
dump kind blobs = case kind of
    "identity" -> Just (identity <$> blob 0 "public key")
    "keyset" -> Just (keyset <$> blob 0 "private key")
    "destination" -> Just (destination <$> blob 0 "name" <*> pure (blobs `at` 1))
    "announce" -> Just (announce <$> blob 0 "packet")
    "plain" -> Just (plain <$> blob 0 "packet")
    "pathrequest" -> Just (pathrequest <$> blob 0 "packet")
    "signature" -> Just (signature <$> blob 0 "public key" <*> blob 1 "message" <*> blob 2 "signature")
    "sign" -> Just (signed <$> blob 0 "private key" <*> blob 1 "message")
    _ -> Nothing
  where
    blob index what = maybe (Left ("raw carries no " ++ what)) Right (blobs `at` index)

-- | corpus doc/identity, vector format: identity.
identity :: ByteString -> [Field]
identity raw = gated (Identity.publicKey raw) publicKeyFields

-- | corpus doc/identity, vector format: keyset. The public half is
-- gated a second time, on the derivation rather than on the blob.
keyset :: ByteString -> [Field]
keyset raw =
    gated key
        [ ("private_key", Hex . Identity.privateKeyBytes)
        , ("x25519_private", Hex . Identity.x25519Private)
        , ("ed25519_private", Hex . Identity.ed25519Private)
        ]
        ++ gated (Identity.toPublic =<< key) publicKeyFields
  where
    key = Identity.privateKey raw

publicKeyFields :: [(String, Identity.PublicKey -> Value)]
publicKeyFields =
    [ ("public_key", Hex . Identity.publicKeyBytes)
    , ("x25519_public", Hex . Identity.x25519Public)
    , ("ed25519_public", Hex . Identity.ed25519Public)
    , ("identity_hash", Hex . Identity.identityHashBytes . Identity.identityHash)
    ]

-- | corpus doc/destination. The second blob is the identity hash, and
-- a name has none as often as it has one. identity_hash is that blob
-- echoed: it is an input here, not something derived.
destination :: ByteString -> Maybe ByteString -> [Field]
destination rawName rawIdentity =
    [ ("name", Hex (Destination.nameBytes name))
    , ("app_name", Hex (Destination.appName name))
    ]
        ++ [("aspect", Hex aspect) | aspect <- Destination.aspects name]
        ++ [ ("name_hash", Hex (Destination.nameHashBytes hash))
           , ("identity_hash", maybe Absent (Hex . Identity.identityHashBytes) holder)
           , ("destination_hash", Hex (Destination.destinationHashBytes address))
           ]
  where
    name = Destination.name rawName
    hash = Destination.nameHash name
    holder = Identity.IdentityHash <$> rawIdentity
    address = Destination.destinationHash hash holder

-- | corpus doc/identity, vector format: signature. The message is
-- recorded by length and digest, which is what makes this kind and the
-- one below the only two the corpus cannot rebuild raw from.
signature :: ByteString -> ByteString -> ByteString -> [Field]
signature rawKey message rawSignature =
    gated key [("ed25519_public", Hex . Identity.ed25519Public)]
        ++ recorded message
        ++ [ ("signature", Hex rawSignature)
           , ("valid", either (const Absent) verdict verified)
           ]
  where
    key = Identity.publicKey rawKey
    verified = (\k -> Identity.validate k message rawSignature) <$> key

-- | corpus doc/identity, vector format: sign. The signature is the
-- answer here rather than an input, and there is no verdict field.
signed :: ByteString -> ByteString -> [Field]
signed rawKey message =
    gated key
        [ ("private_key", Hex . Identity.privateKeyBytes)
        , ("ed25519_private", Hex . Identity.ed25519Private)
        ]
        ++ gated (Identity.toPublic =<< key) [("ed25519_public", Hex . Identity.ed25519Public)]
        ++ recorded message
        ++ [("signature", either (const Absent) Hex (flip Identity.sign message =<< key))]
  where
    key = Identity.privateKey rawKey

recorded :: ByteString -> [Field]
recorded message =
    [ ("message_length", Dec (B.length message))
    , ("message_sha256", Hex (Identity.fullHash message))
    ]

-- | corpus doc/announce.
announce :: ByteString -> [Field]
announce raw = packet raw $ \unpacked ->
    fields (Packet.address unpacked) <$> Announce.announce unpacked
  where
    fields address value =
        [ ("public_key", Hex (Identity.publicKeyBytes (Announce.publicKey value)))
        , ("name_hash", Hex (Destination.nameHashBytes (Announce.nameHash value)))
        , ("random_hash", Hex (Announce.randomHash value))
        , ("ratchet", maybe Absent Hex (Announce.ratchet value))
        , ("signature", Hex (Announce.signature value))
        , ("app_data", Hex (Announce.appData value))
        , ("identity_hash", Hex (Identity.identityHashBytes (Identity.identityHash (Announce.publicKey value))))
        , ("expected_hash", Hex (Destination.destinationHashBytes (Announce.expectedHash value)))
        , ("destination_match", verdict (Announce.destinationMatch address value))
        , ("signed_data", Hex (Announce.signedData address value))
        , ("signature_valid", verdict (Announce.signatureValid address value))
        ]

-- | corpus doc/packet, section Plain destinations. The payload is the
-- data: encryption to a plain destination returns the plaintext
-- unchanged, so there is nothing between the two fields and the packet.
plain :: ByteString -> [Field]
plain raw = packet raw $ \unpacked ->
    Right
        [ ("plaintext_length", Dec (B.length (Packet.payload unpacked)))
        , ("plaintext", Hex (Packet.payload unpacked))
        ]

-- | corpus doc/packet, section Path requests.
pathrequest :: ByteString -> [Field]
pathrequest raw = packet raw $ \unpacked ->
    fields <$> Transport.pathRequest (Packet.payload unpacked)
  where
    fields request =
        [ ("wanted_hash", Hex (Transport.wantedHash request))
        , ("requester_id", maybe Absent Hex (Transport.requesterId request))
        , ("tag", maybe Absent Hex (Transport.tag request))
        , ("unique_tag", maybe Absent Hex (Transport.uniqueTag request))
        , ("accepted", verdict (Transport.accepted request))
        ]

-- | A packet that broke a rule carries the rule and nothing else, and a
-- payload that broke one leaves no header standing either: these rules
-- all say the packet was not read.
packet :: ByteString -> (Packet.Packet -> Either Packet.Rejection [Field]) -> [Field]
packet raw fields = case Packet.unpack raw of
    Left reason -> rejection reason
    Right unpacked -> case fields unpacked of
        Left reason -> rejection reason
        Right rest -> header unpacked ++ rest

header :: Packet.Packet -> [Field]
header unpacked =
    [ ("flags", byte (Packet.flags unpacked))
    , ("header_type", Dec (case Packet.headerType unpacked of Packet.Header1 -> 1; Packet.Header2 -> 2))
    , ("context_flag", Keyword (if Packet.contextFlag unpacked then "set" else "unset"))
    , ("transport_type", Keyword (case Packet.transportType unpacked of Packet.Broadcast -> "broadcast"; Packet.Transport -> "transport"))
    , ("destination_type", Keyword (destinationType (Packet.destinationType unpacked)))
    , ("packet_type", Keyword (packetType (Packet.packetType unpacked)))
    , ("hops", Dec (fromIntegral (Packet.hops unpacked)))
    , ("transport_id", maybe Absent Hex (Packet.transportId unpacked))
    , ("destination_hash", Hex (Packet.address unpacked))
    , ("context", context (Packet.context unpacked))
    , ("payload_length", Dec (B.length (Packet.payload unpacked)))
    ]
  where
    destinationType kind = case kind of
        Packet.Single -> "single"
        Packet.Group -> "group"
        Packet.Plain -> "plain"
        Packet.Link -> "link"
    packetType kind = case kind of
        Packet.Data -> "data"
        Packet.Announce -> "announce"
        Packet.LinkRequest -> "linkrequest"
        Packet.Proof -> "proof"

-- | Rule 2. The format spells a context as a keyword only where a
-- vector carries that byte. Three the reference defines and this
-- implementation names have no keyword, and print as the byte.
context :: Packet.Context -> Value
context named = case named of
    Packet.None -> Keyword "none"
    Packet.Resource -> Keyword "resource"
    Packet.ResourceAdv -> Keyword "resource_adv"
    Packet.ResourceReq -> Keyword "resource_req"
    Packet.ResourceHmu -> Keyword "resource_hmu"
    Packet.ResourcePrf -> Keyword "resource_prf"
    Packet.ResourceIcl -> Keyword "resource_icl"
    Packet.ResourceRcl -> Keyword "resource_rcl"
    Packet.Request -> Keyword "request"
    Packet.Response -> Keyword "response"
    Packet.PathResponse -> Keyword "path_response"
    Packet.Channel -> Keyword "channel"
    Packet.Keepalive -> Keyword "keepalive"
    Packet.LinkIdentify -> Keyword "link_identify"
    Packet.LinkClose -> Keyword "link_close"
    Packet.LinkProof -> Keyword "link_proof"
    Packet.LinkRtt -> Keyword "link_rtt"
    Packet.LinkRequestProof -> Keyword "link_request_proof"
    Packet.CacheRequest -> unnamed
    Packet.Command -> unnamed
    Packet.CommandStatus -> unnamed
    Packet.UnnamedContext _ -> unnamed
  where
    unnamed = byte (Packet.contextByte named)

rejection :: Packet.Rejection -> [Field]
rejection broken = case broken of
    Packet.ShortHeader present needed ->
        [ ("invalid", Keyword "short-header")
        , ("length", Dec present)
        , ("minimum_length", Dec needed)
        ]
    Packet.HopLimit count limit ->
        [ ("invalid", Keyword "hop-limit")
        , ("hops", Dec count)
        , ("hop_limit", Dec limit)
        ]
    Packet.ShortPayload present needed ->
        [ ("invalid", Keyword "short-payload")
        , ("payload_length", Dec present)
        , ("minimum_length", Dec needed)
        ]

-- Fields

data Value
    = Hex ByteString
    | Dec Int
    | Keyword String
    | Absent

type Field = (String, Value)

byte :: Word8 -> Value
byte = Hex . B.singleton

verdict :: Bool -> Value
verdict held = Keyword (if held then "yes" else "no")

-- | Rule 6. What the implementation refused is a dash, and the fields
-- it does not gate still stand.
gated :: Either e a -> [(String, a -> Value)] -> [Field]
gated (Left _) fields = [(name, Absent) | (name, _) <- fields]
gated (Right value) fields = [(name, of' value) | (name, of') <- fields]

-- | Rule 5, in the one place it belongs: the name in 18 columns, the
-- value after it, and the empty byte string as a dash because hex
-- cannot spell one.
render :: Field -> String
render (name, value) = name ++ replicate (nameColumns - length name) ' ' ++ " " ++ text value
  where
    nameColumns = 18
    text Absent = "-"
    text (Dec number) = show number
    text (Keyword word) = word
    text (Hex bytes)
        | B.null bytes = "-"
        | otherwise = C.unpack (Encoding.convertToBase Encoding.Base16 bytes)

-- Raw

-- | raw is one blob per line, hex, or a dash where the kind admits an
-- absent one. No blob carries a space, so the lines are the words.
readBlobs :: FilePath -> IO [Maybe ByteString]
readBlobs path = mapM blob . C.words =<< B.readFile path
  where
    blob token
        | token == C.pack "-" = pure Nothing
        | otherwise = case Encoding.convertFromBase Encoding.Base16 token of
            Left reason -> die (path ++ ": " ++ reason)
            Right bytes -> pure (Just bytes)

at :: [Maybe ByteString] -> Int -> Maybe ByteString
at blobs index = case drop index blobs of
    (blob : _) -> blob
    [] -> Nothing
