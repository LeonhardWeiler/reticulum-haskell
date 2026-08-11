{-# LANGUAGE StrictData #-}

-- | RNS/Transport.py
module Reticulum.Transport
    ( PathRequest (..)
    , pathRequest
    , uniqueTag
    , accepted
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Maybe (isJust)

import Reticulum.Packet (Rejection (ShortPayload), addressLength)

-- | RNS/Transport.py#path_request_handler. Three fields concatenated
-- with no count, no type byte and no delimiter, so which of them are
-- present is decided by the payload length alone. A sender writes the
-- transport id only when it is itself a transport node, and nothing on
-- the wire says whether it did: a 17-byte tag written without one
-- reads as a transport id and a tag of one byte, and there is no
-- correct decoding of that packet.
data PathRequest = PathRequest
    { wantedHash :: ByteString
    , requesterId :: Maybe ByteString
    , tag :: Maybe ByteString
    }

pathRequest :: ByteString -> Either Rejection PathRequest
pathRequest payload
    | length' < addressLength = Left (ShortPayload length' addressLength)
    | length' > 2 * addressLength =
        Right
            (request (Just (part addressLength)) (Just (B.drop (2 * addressLength) payload)))
    | length' > addressLength = Right (request Nothing (Just (B.drop addressLength payload)))
    | otherwise = Right (request Nothing Nothing)
  where
    length' = B.length payload
    part at = B.take addressLength (B.drop at payload)
    request = PathRequest (part 0)

-- | What the duplicate check is made against. At most 16 bytes of the
-- tag reach it, so two requests whose tags agree that far are one
-- request. A request with no tag never reaches the check at all, which
-- is also what makes it one the reference does not act on.
uniqueTag :: PathRequest -> Maybe ByteString
uniqueTag request = mappend (wantedHash request) . B.take addressLength <$> tag request

-- | Whether the handler does anything with the request. A tagless one
-- is read in full and then dropped.
accepted :: PathRequest -> Bool
accepted = isJust . tag
