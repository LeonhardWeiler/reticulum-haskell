-- | The corpus's cmd/dump, over this implementation. The contract is
-- corpus doc/harness; the six rules it names are cited by number below.
module Main (main) where

import qualified Data.ByteArray.Encoding as Encoding
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import System.Environment (getArgs, getProgName)
import System.Exit (ExitCode (ExitFailure), die, exitWith)

import qualified Reticulum.Destination as Destination
import qualified Reticulum.Identity as Identity

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

-- Fields

data Value
    = Hex ByteString
    | Absent

type Field = (String, Value)

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
