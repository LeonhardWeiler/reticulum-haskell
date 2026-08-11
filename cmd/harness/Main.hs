-- | The corpus's cmd/dump, over this implementation. The contract is
-- corpus doc/harness; the six rules it names are cited by number below.
module Main (main) where

import qualified Data.ByteArray.Encoding as Encoding
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import System.Environment (getArgs, getProgName)
import System.Exit (ExitCode (ExitFailure), die, exitWith)

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
                Just fields -> mapM_ (putStrLn . render) fields
        ("-e" : _) -> die "the encode direction is not implemented"
        _ -> do
            name <- getProgName
            die ("usage: " ++ name ++ " <kind> <rawfile>")

dump :: String -> [Maybe ByteString] -> Maybe [Field]
dump kind blobs = case kind of
    "identity" -> Just (identity (blobs `at` 0))
    _ -> Nothing

-- | Every field of test/identity is gated on the one blob being a
-- public key. corpus doc/identity, vector format: identity.
identity :: Maybe ByteString -> [Field]
identity raw =
    gated (Identity.publicKey =<< present "public key" raw) $
        [ ("public_key", Hex . Identity.publicKeyBytes)
        , ("x25519_public", Hex . Identity.x25519Public)
        , ("ed25519_public", Hex . Identity.ed25519Public)
        , ("identity_hash", Hex . Identity.identityHashBytes . Identity.identityHash)
        ]

-- Fields

data Value
    = Hex ByteString
    | Absent

type Field = (String, Value)

-- | Rule 6. What the implementation refused is a dash, and the fields
-- it does not gate still stand.
gated :: Either e a -> [(String, a -> Value)] -> [Field]
gated (Left _) fields = [(name, Absent) | (name, _) <- fields]
gated (Right value) fields = [(name, render' value) | (name, render') <- fields]

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

present :: String -> Maybe ByteString -> Either String ByteString
present what = maybe (Left ("raw carries no " ++ what)) Right
