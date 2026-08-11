module Main (main) where

import Data.Bits (shiftR)
import qualified Data.ByteArray.Encoding as Encoding
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Word (Word16, Word64, Word8)
import System.Environment (getArgs, getProgName)
import System.Exit (ExitCode (ExitFailure), die, exitWith)

import qualified Reticulum.Announce as Announce
import qualified Reticulum.Channel as Channel
import qualified Reticulum.Destination as Destination
import qualified Reticulum.Encryption as Encryption
import qualified Reticulum.Identity as Identity
import qualified Reticulum.Interface as Interface
import qualified Reticulum.Link as Link
import qualified Reticulum.Packet as Packet
import qualified Reticulum.Proof as Proof
import qualified Reticulum.Request as Request
import qualified Reticulum.Resource as Resource
import qualified Reticulum.Token as Token
import qualified Reticulum.Transport as Transport

main :: IO ()
main = do
    args <- getArgs
    case args of
        [kind, path] -> do
            blobs <- readBlobs path
            case dump kind blobs of
                -- 77 says the kind is not implemented, and nothing else
                -- may use it.
                Nothing -> exitWith (ExitFailure 77)
                Just (Left reason) -> die (path ++ ": " ++ reason)
                Just (Right fields) -> mapM_ (putStrLn . render) fields
        ["-e", kind, path] -> do
            fields <- readFields path
            case encode kind fields of
                Nothing -> exitWith (ExitFailure 77)
                Just (Left reason) -> die (path ++ ": " ++ reason)
                Just (Right raw) -> mapM_ putStrLn raw
        _ -> do
            name <- getProgName
            die ("usage: " ++ name ++ " <kind> <rawfile>\n       " ++ name ++ " -e <kind> <expectfile>")

-- | Nothing for a kind this harness has not implemented, Left for a raw
-- that does not carry what the kind holds.
dump :: String -> [Maybe ByteString] -> Maybe (Either String [Field])
dump kind blobs = case kind of
    "identity" -> Just (identity <$> blob 0 "public key")
    "keyset" -> Just (keyset <$> blob 0 "private key")
    "destination" -> Just (destination <$> blob 0 "name" <*> pure (blobs `at` 1))
    "announce" -> Just (announce <$> blob 0 "packet")
    "plain" -> Just (plain <$> blob 0 "packet")
    "pathrequest" -> Just (pathrequest <$> blob 0 "packet")
    "group" -> Just (group <$> blob 0 "group key" <*> blob 1 "packet")
    "encrypted" ->
        Just (encrypted <$> blob 0 "recipient private key" <*> pure (blobs `at` 1) <*> blob 2 "packet")
    "proof" -> Just (proof <$> blob 0 "proved packet" <*> blob 1 "public key" <*> blob 2 "packet")
    "linkrequest" -> Just (linkrequest <$> blob 0 "packet")
    "linkproof" -> Just (linkproof <$> blob 0 "link request" <*> blob 1 "public key" <*> blob 2 "packet")
    "linkdata" ->
        Just (linkdata <$> blob 0 "link request" <*> blob 1 "responder private key" <*> blob 2 "packet")
    "resourceproof" -> Just (resourceproof <$> blob 0 "resource hash" <*> blob 1 "packet")
    "ifac" ->
        Just
            ( ifac (blobs `at` 0) (blobs `at` 1)
                <$> blob 2 "access code size"
                <*> blob 3 "frame"
            )
    "signature" -> Just (signature <$> blob 0 "public key" <*> blob 1 "message" <*> blob 2 "signature")
    "sign" -> Just (signed <$> blob 0 "private key" <*> blob 1 "message")
    _ -> Nothing
  where
    blob index what = maybe (Left ("raw carries no " ++ what)) Right (blobs `at` index)

identity :: ByteString -> [Field]
identity raw = gated (Identity.publicKey raw) publicKeyFields

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

plain :: ByteString -> [Field]
plain raw = packet raw $ \unpacked ->
    Right
        [ ("plaintext_length", Dec (B.length (Packet.payload unpacked)))
        , ("plaintext", Hex (Packet.payload unpacked))
        ]

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

group :: ByteString -> ByteString -> [Field]
group key raw =
    ("group_key", Hex key)
        : packet raw (\unpacked -> fields <$> Token.token (Packet.payload unpacked))
  where
    halves = Token.keys key
    fields value =
        carried value
            ++ [ ("signing_key", Hex (Token.signingKey halves))
               , ("encryption_key", Hex (Token.encryptionKey halves))
               ]
            ++ opened halves value

encrypted :: ByteString -> Maybe ByteString -> ByteString -> [Field]
encrypted rawKey rawRatchet raw =
    [ ("recipient_private", Hex rawKey)
    , ("ratchet_private", maybe Absent Hex rawRatchet)
    ]
        ++ packet raw (\unpacked -> fields <$> Encryption.encrypted (Packet.payload unpacked))
  where
    recipient = Identity.privateKey rawKey
    salt = Identity.identityHashBytes . Identity.identityHash <$> (Identity.toPublic =<< recipient)
    scalar = maybe (Identity.x25519Private <$> recipient) Right rawRatchet

    fields value =
        ("ephemeral_public", Hex (Encryption.ephemeralPublic value))
            : carried (Encryption.token value)
            ++ [ ("identity_hash", either (const Absent) Hex salt)
               , ("ratchet_public", maybe Absent (maybe Absent Hex . Encryption.publicPoint) rawRatchet)
               ]
            ++ agreement (Encryption.token value) (secret (Encryption.ephemeralPublic value))

    secret ephemeral = do
        own <- either (const Nothing) Just scalar
        recipientHash <- either (const Nothing) Just salt
        agreed <- Encryption.shared own ephemeral
        Just (agreed, Token.keys (Encryption.derive Encryption.derivedKeyLength agreed recipientHash))

agreement :: Token.Token -> Maybe (ByteString, Token.Keys) -> [Field]
agreement _ Nothing =
    [ ("shared_key", Absent)
    , ("signing_key", Absent)
    , ("encryption_key", Absent)
    , ("hmac_valid", Absent)
    ]
        ++ plaintext Nothing
agreement value (Just (agreed, halves)) =
    [ ("shared_key", Hex agreed)
    , ("signing_key", Hex (Token.signingKey halves))
    , ("encryption_key", Hex (Token.encryptionKey halves))
    ]
        ++ opened halves value

linkrequest :: ByteString -> [Field]
linkrequest raw = packet raw $ \unpacked ->
    fields unpacked <$> Link.request (Packet.payload unpacked)
  where
    fields unpacked value =
        ("x25519_public", Hex (Link.x25519Public value))
            : ("ed25519_public", Hex (Link.ed25519Public value))
            : signalled (Link.requestSignalling value)
            ++ [("link_id", Hex (Link.linkId unpacked))]

linkproof :: ByteString -> ByteString -> ByteString -> [Field]
linkproof requestRaw signerKey raw =
    [ ("link_request", Hex requestRaw)
    , ("signer_public", Hex signerKey)
    ]
        ++ packet raw (\unpacked -> fields unpacked <$> Link.requestProof (Packet.payload unpacked))
  where
    link = Link.linkId <$> Packet.unpack requestRaw
    signerEd = either (const signerKey) Identity.ed25519Public (Identity.publicKey signerKey)

    fields unpacked value =
        [ ("link_id", either (const Absent) Hex link)
        , ("link_id_match", either (const Absent) (verdict . (Packet.address unpacked ==)) link)
        , ("signature", Hex (Link.signature value))
        , ("x25519_public", Hex (Link.responderPublic value))
        ]
            ++ signalled (Link.proofSignalling value)
            ++ [ ("signer_ed25519", Hex signerEd)
               , ("signed_data", either (const Absent) (\l -> Hex (Link.signedData l signerEd value)) link)
               , ( "signature_valid"
                 , either (const Absent) (\l -> verdict (Link.signatureValid l signerEd value)) link
                 )
               ]

linkdata :: ByteString -> ByteString -> ByteString -> [Field]
linkdata requestRaw responderKey raw =
    [ ("link_request", Hex requestRaw)
    , ("responder_private", Hex responderKey)
    ]
        ++ carriedOn raw fields
  where
    opening = do
        unpacked <- either (const Nothing) Just (Packet.unpack requestRaw)
        value <- either (const Nothing) Just (Link.request (Packet.payload unpacked))
        Just (Link.linkId unpacked, Link.x25519Public value)
    secret = (\(link, peer) -> Link.handshake responderKey peer link) =<< opening

    fields unpacked =
        [ ("link_id", maybe Absent (Hex . fst) opening)
        , ("link_id_match", maybe Absent (verdict . (Packet.address unpacked ==) . fst) opening)
        , ("encrypted", verdict (Packet.encrypted unpacked))
        ]
            ++ body unpacked

    body unpacked
        | Packet.encrypted unpacked =
            either rejection (token unpacked) (Token.token (Packet.payload unpacked))
        | otherwise = plaintext (Just (Packet.payload unpacked)) ++ contents unpacked (Packet.payload unpacked)

    token unpacked value =
        carried value
            ++ agreement value ((\held -> (Link.shared held, Link.keys held)) <$> secret)
            ++ maybe [] (contents unpacked) (flip Token.open value . Link.keys =<< secret)

    contents unpacked = either rejection id . decompose (fst <$> opening) (Packet.context unpacked)

decompose :: Maybe ByteString -> Packet.Context -> ByteString -> Either Packet.Rejection [Field]
decompose link named bytes = case named of
    Packet.LinkIdentify -> Right (identify link bytes)
    Packet.Channel -> channel <$> Channel.envelope bytes
    Packet.Request -> asked <$> Request.request bytes
    Packet.Response -> answered <$> Request.response bytes
    Packet.ResourceAdv -> advertisement <$> Resource.advertisement bytes
    Packet.ResourceReq -> partRequest <$> Resource.partRequest bytes
    Packet.ResourceHmu -> update <$> Resource.update bytes
    Packet.ResourceIcl -> Right [("resource_hash", Hex (Resource.cancel bytes))]
    Packet.ResourceRcl -> Right [("resource_hash", Hex (Resource.cancel bytes))]
    _ -> Right []

asked :: Request.Request -> [Field]
asked value =
    [ ("request_time", maybe Absent Hex (Request.time value))
    , ("request_path_hash", maybe Absent Hex (Request.pathHash value))
    , ("request_data", maybe Absent Hex (Request.requestBody value))
    ]

answered :: Request.Response -> [Field]
answered value =
    [ ("request_id", maybe Absent Hex (Request.requestId value))
    , ("response_data", maybe Absent Hex (Request.responseBody value))
    ]

advertisement :: Resource.Advertisement -> [Field]
advertisement value =
    [ ("transfer_size", counted (Resource.transferSize value))
    , ("data_size", counted (Resource.dataSize value))
    , ("resource_parts", counted (Resource.parts value))
    , ("resource_hash", maybe Absent Hex (Resource.resourceHash value))
    , ("resource_random", maybe Absent Hex (Resource.randomHash value))
    , ("original_hash", maybe Absent Hex (Resource.originalHash value))
    , ("segment_index", counted (Resource.segmentIndex value))
    , ("total_segments", counted (Resource.totalSegments value))
    , ("request_id", maybe Absent Hex (Resource.requestId value))
    , ("resource_flags", maybe Absent byte (Resource.flags value))
    , ("hashmap", maybe Absent Hex (Resource.hashmap value))
    ]

partRequest :: Resource.PartRequest -> [Field]
partRequest value =
    [ ("hashmap_exhausted", verdict (Resource.exhausted value))
    , ("last_map_hash", maybe Absent Hex (Resource.lastMapHash value))
    , ("resource_hash", Hex (Resource.requestedResource value))
    , ("requested_hashes", Hex (Resource.requestedHashes value))
    ]

update :: Resource.Update -> [Field]
update value =
    [ ("resource_hash", Hex (Resource.updatedResource value))
    , ("segment_index", counted (Resource.updateSegment value))
    , ("hashmap", maybe Absent Hex (Resource.updateHashmap value))
    ]

resourceproof :: ByteString -> ByteString -> [Field]
resourceproof advertised raw =
    ("advertised_hash", Hex advertised)
        : carriedOn raw (either rejection fields . Resource.proof . Packet.payload)
  where
    fields value =
        [ ("resource_hash", Hex (Resource.provedResource value))
        , ("resource_proof", Hex (Resource.dataHash value))
        , ("hash_match", verdict (Resource.provedResource value == advertised))
        ]

ifac :: Maybe ByteString -> Maybe ByteString -> ByteString -> ByteString -> [Field]
ifac netname netkey rawSize raw =
    [ ("netname", maybe Absent Hex netname)
    , ("netkey", maybe Absent Hex netkey)
    , ("ifac_origin", maybe Absent (Hex . Interface.origin) held)
    , ("ifac_key", maybe Absent (Hex . Interface.key) held)
    , ("ifac_size", Dec size)
    , ("frame_length", Dec (B.length raw))
    , ("ifac", maybe Absent (Hex . Interface.code) framed)
    , ("packet", maybe Absent (Hex . Interface.packet) framed)
    , ("expected_ifac", maybe Absent Hex expected)
    , ("ifac_valid", maybe Absent verdict ((==) <$> (Interface.code <$> framed) <*> expected))
    ]
  where
    size = B.foldl' (\value read' -> value * 256 + fromIntegral read') 0 rawSize
    held = Interface.access netname netkey
    framed = (\value -> Interface.frame value size raw) =<< held
    expected = do
        value <- held
        recovered <- framed
        Interface.codeFor value size (Interface.packet recovered)

counted :: Maybe Word64 -> Value
counted = maybe Absent (Dec . fromIntegral)

identify :: Maybe ByteString -> ByteString -> [Field]
identify link bytes = case Link.identify bytes of
    Nothing ->
        [ ("identity_public", Absent)
        , ("identity_hash", Absent)
        , ("identity_signed", Absent)
        , ("identity_valid", Absent)
        ]
    Just value ->
        [ ("identity_public", Hex (Identity.publicKeyBytes (Link.identityPublic value)))
        , ("identity_hash", Hex (Identity.identityHashBytes (Identity.identityHash (Link.identityPublic value))))
        , ("identity_signed", maybe Absent (\l -> Hex (Link.identifySigned l value)) link)
        , ("identity_valid", maybe Absent (\l -> verdict (Link.identifyValid l value)) link)
        ]

channel :: Channel.Envelope -> [Field]
channel value =
    [ ("msgtype", word16 (Channel.messageType value))
    , ("sequence", Dec (fromIntegral (Channel.sequence value)))
    , ("declared_length", Dec (fromIntegral (Channel.declaredLength value)))
    , ("message", Hex (Channel.message value))
    ]

-- | The format spells a mode as a keyword only where a vector carries
-- the bits, so the one the reference defines and never sends is a byte.
signalled :: Maybe ByteString -> [Field]
signalled bytes =
    [ ("signalling", maybe Absent Hex bytes)
    , ("mode", if named == Link.modeAes256Cbc then Keyword "aes256_cbc" else byte named)
    , ("mtu", maybe Absent Dec (Link.mtu bytes))
    ]
  where
    named = Link.mode bytes

proof :: ByteString -> ByteString -> ByteString -> [Field]
proof provedRaw signerKey raw =
    [ ("proved_packet", Hex provedRaw)
    , ("signer_public", Hex signerKey)
    ]
        ++ packet raw (\unpacked -> fields unpacked <$> Proof.proof (Packet.payload unpacked))
  where
    proved = Packet.unpack provedRaw
    computed = Packet.packetHash <$> proved
    signerEd = either (const signerKey) Identity.ed25519Public (Identity.publicKey signerKey)

    fields unpacked value =
        [ ("form", Keyword (case Proof.form value of Proof.Implicit -> "implicit"; Proof.Explicit -> "explicit"))
        , ("packet_hash", either (const Absent) Hex computed)
        , ("proof_hash", maybe Absent Hex (Proof.provedHash value))
        , ("hash_match", either (const Absent) (\hash -> verdict (Proof.hashMatch hash value)) computed)
        ]
            ++ addressed unpacked
            ++ [ ("signature", Hex (Proof.signature value))
               , ("signer_ed25519", Hex signerEd)
               , ( "signature_valid"
                 , either (const Absent) (\hash -> verdict (Proof.signatureValid signerEd hash value)) computed
                 )
               ]

    addressed unpacked = case Packet.destinationType unpacked of
        Packet.Link ->
            [ ("link_id", either (const Absent) (Hex . Packet.address) proved)
            , ("link_id_match", either (const Absent) (verdict . sameAddress unpacked . Packet.address) proved)
            ]
        _ ->
            [ ("proof_destination", either (const Absent) (Hex . Proof.proofDestination) computed)
            , ( "destination_match"
              , either (const Absent) (verdict . sameAddress unpacked . Proof.proofDestination) computed
              )
            ]
    sameAddress unpacked = (Packet.address unpacked ==)

carried :: Token.Token -> [Field]
carried value =
    [ ("iv", Hex (Token.iv value))
    , ("ciphertext", Hex (Token.ciphertext value))
    , ("hmac", Hex (Token.hmac value))
    ]

opened :: Token.Keys -> Token.Token -> [Field]
opened halves value =
    ("hmac_valid", verdict (Token.hmacValid halves value)) : plaintext (Token.open halves value)

plaintext :: Maybe ByteString -> [Field]
plaintext Nothing = [("plaintext_length", Absent), ("plaintext", Absent)]
plaintext (Just bytes) = [("plaintext_length", Dec (B.length bytes)), ("plaintext", Hex bytes)]

packet :: ByteString -> (Packet.Packet -> Either Packet.Rejection [Field]) -> [Field]
packet raw fields = case Packet.unpack raw of
    Left reason -> rejection reason
    Right unpacked -> case fields unpacked of
        Left reason -> rejection reason
        Right rest -> header unpacked ++ rest

-- | A payload rejection on a link stands behind the fields that were
-- read before it rather than deleting them.
carriedOn :: ByteString -> (Packet.Packet -> [Field]) -> [Field]
carriedOn raw fields = case Packet.unpack raw of
    Left reason -> rejection reason
    Right unpacked -> header unpacked ++ fields unpacked

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

-- | The field format spells a context as a keyword only where a vector
-- carries the byte, so three of them print as the byte instead.
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
    Packet.SignalledLength present accepted withSignalling ->
        [ ("invalid", Keyword "invalid-length")
        , ("payload_length", Dec present)
        , ("accepted_length", Dec accepted)
        , ("signalled_length", Dec withSignalling)
        ]
    Packet.ShortPlaintext needed ->
        [ ("invalid", Keyword "short-plaintext")
        , ("minimum_length", Dec needed)
        ]
    Packet.FixedLength present accepted ->
        [ ("invalid", Keyword "invalid-length")
        , ("payload_length", Dec present)
        , ("accepted_length", Dec accepted)
        ]
    Packet.ProofLength present implicit explicit ->
        [ ("invalid", Keyword "invalid-length")
        , ("payload_length", Dec present)
        , ("implicit_length", Dec implicit)
        , ("explicit_length", Dec explicit)
        ]

data Value
    = Hex ByteString
    | Dec Int
    | Keyword String
    | Absent

type Field = (String, Value)

-- | A field the implementation produced nothing for is a dash, and the
-- fields it does not gate still stand.
gated :: Either e a -> [(String, a -> Value)] -> [Field]
gated (Left _) fields = [(name, Absent) | (name, _) <- fields]
gated (Right value) fields = [(name, of' value) | (name, of') <- fields]

-- | The empty byte string is a dash because hex cannot spell one.
render :: Field -> String
render (name, value) = name ++ replicate (nameColumns - length name) ' ' ++ " " ++ text value
  where
    nameColumns = 18
    text Absent = "-"
    text (Dec number) = show number
    text (Keyword word) = word
    text (Hex bytes)
        | B.null bytes = "-"
        | otherwise = hex bytes

hex :: ByteString -> String
hex = C.unpack . Encoding.convertToBase Encoding.Base16

byte :: Word8 -> Value
byte = Hex . B.singleton

word16 :: Word16 -> Value
word16 value = Hex (B.pack [fromIntegral (value `shiftR` 8), fromIntegral value])

verdict :: Bool -> Value
verdict held = Keyword (if held then "yes" else "no")

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

-- | Writing raw back from the fields. The table this runs from is its
-- own, and the round trip is what holds it to the one the decoders
-- read.
type Fields = [(String, String)]

encode :: String -> Fields -> Maybe (Either String [String])
encode kind fields = case kind of
    "identity" -> Just (echoed ["public_key"])
    "keyset" -> Just (echoed ["private_key"])
    "destination" -> Just (echoed ["name", "identity_hash"])
    "plain" -> Just (rebuilt [] (part fields "plaintext"))
    "announce" -> Just (rebuilt [] (announced fields))
    "pathrequest" -> Just (rebuilt [] (asking fields))
    "group" -> Just (rebuilt ["group_key"] (Token.pack <$> sealed fields))
    "encrypted" ->
        Just
            ( rebuilt
                ["recipient_private", "ratchet_private"]
                (Encryption.pack <$> (Encryption.Encrypted <$> part fields "ephemeral_public" <*> sealed fields))
            )
    "linkrequest" -> Just (rebuilt [] (requesting fields))
    "linkproof" -> Just (rebuilt ["link_request", "signer_public"] (proving fields))
    "linkdata" -> Just (rebuilt ["link_request", "responder_private"] (onLink fields))
    "proof" ->
        Just
            ( rebuilt
                ["proved_packet", "signer_public"]
                (fmap Proof.pack (Proof.Proof <$> given fields "proof_hash" <*> part fields "signature"))
            )
    "resourceproof" ->
        Just
            ( rebuilt
                ["advertised_hash"]
                ( fmap Resource.packProof $
                    Resource.Proof <$> part fields "resource_hash" <*> part fields "resource_proof"
                )
            )
    "ifac" -> Just (masking fields)
    _ -> Nothing
  where
    echoed = mapM (written fields)

    rebuilt echoes body = do
        first <- echoed echoes
        built <- packed fields =<< body
        pure (first ++ [hex built])

-- | The size raw carries is the length of the code, and the frame is
-- the one line the encoders do not simply lay end to end.
masking :: Fields -> Either String [String]
masking fields = do
    name <- given fields "netname"
    passphrase <- given fields "netkey"
    accessed <- part fields "ifac"
    inner <- part fields "packet"
    held <-
        maybe (Left "expect names neither a netname nor a netkey") Right (Interface.access name passphrase)
    built <-
        maybe (Left "the packet is too short to carry a header") Right $
            Interface.pack held (Interface.Frame accessed inner)
    echoes <- mapM (written fields) ["netname", "netkey"]
    pure (echoes ++ [hex (B.singleton (fromIntegral (B.length accessed))), hex built])

requesting :: Fields -> Either String ByteString
requesting fields =
    fmap Link.packRequest $
        Link.Request
            <$> part fields "x25519_public"
            <*> part fields "ed25519_public"
            <*> given fields "signalling"

proving :: Fields -> Either String ByteString
proving fields =
    fmap Link.packRequestProof $
        Link.RequestProof
            <$> part fields "signature"
            <*> part fields "x25519_public"
            <*> given fields "signalling"

-- | Which of the two a link packet holds is the packet's own rule, and
-- the payload it is asked about does not enter into it.
onLink :: Fields -> Either String ByteString
onLink fields = do
    shape <- shaped fields B.empty
    if Packet.encrypted shape
        then Token.pack <$> sealed fields
        else part fields "plaintext"

sealed :: Fields -> Either String Token.Token
sealed fields =
    Token.Token
        <$> part fields "iv"
        <*> part fields "ciphertext"
        <*> part fields "hmac"

announced :: Fields -> Either String ByteString
announced fields = do
    key <- Identity.publicKey =<< part fields "public_key"
    name <- part fields "name_hash"
    random <- part fields "random_hash"
    turning <- given fields "ratchet"
    signed' <- part fields "signature"
    trailing <- part fields "app_data"
    pure
        ( Announce.pack
            Announce.Announce
                { Announce.publicKey = key
                , Announce.nameHash = Destination.NameHash name
                , Announce.randomHash = random
                , Announce.ratchet = turning
                , Announce.signature = signed'
                , Announce.appData = trailing
                }
        )

asking :: Fields -> Either String ByteString
asking fields = do
    wanted <- part fields "wanted_hash"
    asker <- given fields "requester_id"
    marked <- given fields "tag"
    pure
        ( Transport.pack
            Transport.PathRequest
                { Transport.wantedHash = wanted
                , Transport.requesterId = asker
                , Transport.tag = marked
                }
        )

packed :: Fields -> ByteString -> Either String ByteString
packed fields body = Packet.pack <$> shaped fields body

shaped :: Fields -> ByteString -> Either String Packet.Packet
shaped fields body = do
    flagged <- keyword fields "context_flag" [("set", True), ("unset", False)]
    transport <-
        keyword
            fields
            "transport_type"
            [("broadcast", Packet.Broadcast), ("transport", Packet.Transport)]
    toward <-
        keyword
            fields
            "destination_type"
            [ ("single", Packet.Single)
            , ("group", Packet.Group)
            , ("plain", Packet.Plain)
            , ("link", Packet.Link)
            ]
    kind <-
        keyword
            fields
            "packet_type"
            [ ("data", Packet.Data)
            , ("announce", Packet.Announce)
            , ("linkrequest", Packet.LinkRequest)
            , ("proof", Packet.Proof)
            ]
    count <- decimal fields "hops"
    relay <- given fields "transport_id"
    hashed <- part fields "destination_hash"
    named <- contextOf fields
    pure
        Packet.Packet
            { Packet.contextFlag = flagged
            , Packet.transportType = transport
            , Packet.destinationType = toward
            , Packet.packetType = kind
            , Packet.hops = fromIntegral count
            , Packet.transportId = relay
            , Packet.address = hashed
            , Packet.context = named
            , Packet.payload = body
            }

contextOf :: Fields -> Either String Packet.Context
contextOf fields = do
    value <- written fields "context"
    case lookup value names of
        Just found -> Right found
        Nothing -> case B.unpack <$> unhex "context" value of
            Right [single] -> Right (Packet.toContext single)
            _ -> Left ("unusable context " ++ value)
  where
    names =
        [ ("none", Packet.None)
        , ("resource", Packet.Resource)
        , ("resource_adv", Packet.ResourceAdv)
        , ("resource_req", Packet.ResourceReq)
        , ("resource_hmu", Packet.ResourceHmu)
        , ("resource_prf", Packet.ResourcePrf)
        , ("resource_icl", Packet.ResourceIcl)
        , ("resource_rcl", Packet.ResourceRcl)
        , ("request", Packet.Request)
        , ("response", Packet.Response)
        , ("path_response", Packet.PathResponse)
        , ("channel", Packet.Channel)
        , ("keepalive", Packet.Keepalive)
        , ("link_identify", Packet.LinkIdentify)
        , ("link_close", Packet.LinkClose)
        , ("link_proof", Packet.LinkProof)
        , ("link_rtt", Packet.LinkRtt)
        , ("link_request_proof", Packet.LinkRequestProof)
        ]

written :: Fields -> String -> Either String String
written fields name = maybe (Left ("expect carries no " ++ name)) Right (lookup name fields)

-- | A dash carries no bytes, which is how the field format spells every
-- optional part of a payload.
part :: Fields -> String -> Either String ByteString
part fields name = maybe B.empty id <$> given fields name

given :: Fields -> String -> Either String (Maybe ByteString)
given fields name = do
    value <- written fields name
    if value == "-"
        then Right Nothing
        else Just <$> unhex name value

unhex :: String -> String -> Either String ByteString
unhex name value = case Encoding.convertFromBase Encoding.Base16 (C.pack value) of
    Left reason -> Left (name ++ ": " ++ reason)
    Right bytes -> Right bytes

keyword :: Fields -> String -> [(String, a)] -> Either String a
keyword fields name table = do
    value <- written fields name
    maybe (Left ("unusable " ++ name ++ " " ++ value)) Right (lookup value table)

decimal :: Fields -> String -> Either String Int
decimal fields name = do
    value <- written fields name
    case reads value of
        [(read', "")] -> Right read'
        _ -> Left ("unusable " ++ name ++ " " ++ value)

readFields :: FilePath -> IO Fields
readFields path = map field . C.lines <$> B.readFile path
  where
    field line = case C.words line of
        (name : rest) -> (C.unpack name, unwords (map C.unpack rest))
        [] -> ("", "")
