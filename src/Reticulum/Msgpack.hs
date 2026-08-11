{-# LANGUAGE StrictData #-}

module Reticulum.Msgpack
    ( Value (..)
    , unpack
    , element
    , entry
    ) where

import Data.Bits (shiftL, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word (Word64)

data Value
    = Nil
    | Unsigned Word64
    | Float ByteString
    | Bytes ByteString
    | Text ByteString
    | Array [Value]
    | Map [(Value, Value)]
    deriving (Eq)

-- | Bytes after the value are ignored, because every call site hands a
-- whole plaintext to a reader that returns one value and discards them.
unpack :: ByteString -> Maybe Value
unpack = fmap fst . value

element :: Int -> Value -> Maybe Value
element index (Array values) = case drop index values of
    (held : _) -> Just held
    [] -> Nothing
element _ _ = Nothing

entry :: ByteString -> Value -> Maybe Value
entry key (Map keyed) = lookup (Text key) keyed
entry _ _ = Nothing

value :: ByteString -> Maybe (Value, ByteString)
value bytes = do
    (marker, rest) <- B.uncons bytes
    case marker of
        0xc0 -> Just (Nil, rest)
        0xcb -> sized 8 Float rest
        0xc4 -> counted 1 Bytes rest
        0xc5 -> counted 2 Bytes rest
        0xc6 -> counted 4 Bytes rest
        0xcc -> number 1 rest
        0xcd -> number 2 rest
        0xce -> number 4 rest
        0xcf -> number 8 rest
        0xd9 -> counted 1 Text rest
        0xda -> counted 2 Text rest
        0xdb -> counted 4 Text rest
        0xdc -> lengthy 2 array rest
        0xdd -> lengthy 4 array rest
        0xde -> lengthy 2 pairs rest
        0xdf -> lengthy 4 pairs rest
        _
            | marker < 0x80 -> Just (Unsigned (fromIntegral marker), rest)
            | marker .&. 0xf0 == 0x80 -> Just (pairs (fromIntegral (marker .&. 0x0f)) rest)
            | marker .&. 0xf0 == 0x90 -> Just (array (fromIntegral (marker .&. 0x0f)) rest)
            | marker .&. 0xe0 == 0xa0 -> sized (fromIntegral (marker .&. 0x1f)) Text rest
            | otherwise -> Nothing

sized :: Int -> (ByteString -> Value) -> ByteString -> Maybe (Value, ByteString)
sized size held bytes
    | B.length bytes < size = Nothing
    | otherwise = Just (held (B.take size bytes), B.drop size bytes)

counted :: Int -> (ByteString -> Value) -> ByteString -> Maybe (Value, ByteString)
counted width held bytes = do
    (size, rest) <- bigEndian width bytes
    sized (fromIntegral size) held rest

number :: Int -> ByteString -> Maybe (Value, ByteString)
number width bytes = do
    (read', rest) <- bigEndian width bytes
    Just (Unsigned read', rest)

lengthy ::
    Int -> (Int -> ByteString -> (Value, ByteString)) -> ByteString -> Maybe (Value, ByteString)
lengthy width held bytes = do
    (count, rest) <- bigEndian width bytes
    Just (held (fromIntegral count) rest)

bigEndian :: Int -> ByteString -> Maybe (Word64, ByteString)
bigEndian width bytes
    | B.length bytes < width = Nothing
    | otherwise = Just (read', B.drop width bytes)
  where
    read' = B.foldl' (\held byte -> (held `shiftL` 8) .|. fromIntegral byte) 0 (B.take width bytes)

-- | A body that announces more than it holds yields what it held, and
-- the reader stops reading rather than stopping.
array :: Int -> ByteString -> (Value, ByteString)
array count bytes = (Array held, rest)
  where
    (held, rest) = many count bytes

many :: Int -> ByteString -> ([Value], ByteString)
many count bytes
    | count <= 0 = ([], bytes)
    | otherwise = case value bytes of
        Nothing -> ([], bytes)
        Just (held, after) -> let (more, rest) = many (count - 1) after in (held : more, rest)

pairs :: Int -> ByteString -> (Value, ByteString)
pairs count bytes = (Map held, rest)
  where
    (held, rest) = twos count bytes

twos :: Int -> ByteString -> ([(Value, Value)], ByteString)
twos count bytes
    | count <= 0 = ([], bytes)
    | otherwise = case both of
        Nothing -> ([], bytes)
        Just (pair, after) -> let (more, rest) = twos (count - 1) after in (pair : more, rest)
  where
    both = do
        (key, after) <- value bytes
        (held, rest) <- value after
        Just ((key, held), rest)
