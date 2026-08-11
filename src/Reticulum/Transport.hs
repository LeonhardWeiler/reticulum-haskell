{-# LANGUAGE StrictData #-}

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

data PathRequest = PathRequest
    { wantedHash :: ByteString
    , requesterId :: Maybe ByteString
    , tag :: Maybe ByteString
    }

-- | Nothing delimits the three fields, so a 17-byte tag sent without a
-- requester reads as a requester and a one-byte tag.
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

uniqueTag :: PathRequest -> Maybe ByteString
uniqueTag request = mappend (wantedHash request) . B.take addressLength <$> tag request

-- | A request with no tag reaches no duplicate check and is dropped
-- after it has been read.
accepted :: PathRequest -> Bool
accepted = isJust . tag
