{-# LANGUAGE StrictData #-}

module Reticulum.Request
    ( Request (..)
    , request
    , Response (..)
    , response
    , packResponse
    , named
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import qualified Reticulum.Identity as Identity
import qualified Reticulum.Msgpack as Msgpack
import Reticulum.Packet (Rejection (ShortPlaintext))

-- | The time is kept as the eight bytes it arrived in, which is what a
-- reader has to write back to reproduce the packet.
data Request = Request
    { time :: Maybe ByteString
    , pathHash :: Maybe ByteString
    , requestBody :: Maybe ByteString
    }

request :: ByteString -> Either Rejection Request
request plain
    | B.null plain = Left (ShortPlaintext 1)
    | otherwise = Right (Request (float packed 0) (binary packed 1) (binary packed 2))
  where
    packed = Msgpack.unpack plain

-- | The id names the request packet the receiver hashed, not the
-- request it carried.
data Response = Response
    { requestId :: Maybe ByteString
    , responseBody :: Maybe ByteString
    }

response :: ByteString -> Either Rejection Response
response plain
    | B.null plain = Left (ShortPlaintext 1)
    | otherwise = Right (Response (binary packed 0) (binary packed 1))
  where
    packed = Msgpack.unpack plain

packResponse :: ByteString -> ByteString -> ByteString
packResponse identifier body =
    Msgpack.pack (Msgpack.Array [Msgpack.Bytes identifier, Msgpack.Bytes body])

-- | A path is carried as the hash of the bytes of its name and never as
-- the name.
named :: ByteString -> ByteString
named = Identity.truncatedHash

float :: Maybe Msgpack.Value -> Int -> Maybe ByteString
float packed index = case Msgpack.element index =<< packed of
    Just (Msgpack.Float bytes) -> Just bytes
    _ -> Nothing

-- | Nil and a byte string of no bytes are different on the wire and the
-- same absence here.
binary :: Maybe Msgpack.Value -> Int -> Maybe ByteString
binary packed index = case Msgpack.element index =<< packed of
    Just (Msgpack.Bytes bytes) -> Just bytes
    _ -> Nothing
