{-# LANGUAGE StrictData #-}

module Reticulum.Msgpack
    ( Value (..)
    , unpack
    , pack
    , double
    , element
    , entry
    ) where

import Data.Bits ((.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word (Word64, Word8)
import GHC.Float (castDoubleToWord64)

import qualified Reticulum.Bytes as Bytes

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

-- | The shortest form a value fits in is the one written, which is what
-- a reader on the other side compares against.
pack :: Value -> ByteString
pack Nil = B.singleton 0xc0
pack (Unsigned count)
    | count < 0x80 = B.singleton (fromIntegral count)
    | count <= 0xff = marked 0xcc 1 count
    | count <= 0xffff = marked 0xcd 2 count
    | count <= 0xffffffff = marked 0xce 4 count
    | otherwise = marked 0xcf 8 count
pack (Float bytes) = B.singleton 0xcb <> bytes
pack (Bytes bytes) = prefixed 0xc4 0xc5 0xc6 bytes <> bytes
pack (Text bytes)
    | B.length bytes < 0x20 = B.singleton (0xa0 .|. fromIntegral (B.length bytes)) <> bytes
    | otherwise = prefixed 0xd9 0xda 0xdb bytes <> bytes
pack (Array values) = counting 0x90 0xdc 0xdd (length values) <> B.concat (map pack values)
pack (Map keyed) =
    counting 0x80 0xde 0xdf (length keyed)
        <> B.concat [pack key <> pack held | (key, held) <- keyed]

-- | Eight bytes wide, never the four a smaller number would fit in.
double :: Double -> Value
double = Float . Bytes.bigEndianOf 8 . castDoubleToWord64

marked :: Word8 -> Int -> Word64 -> ByteString
marked marker width count = B.singleton marker <> Bytes.bigEndianOf width count

prefixed :: Word8 -> Word8 -> Word8 -> ByteString -> ByteString
prefixed one two four bytes
    | size <= 0xff = marked one 1 (fromIntegral size)
    | size <= 0xffff = marked two 2 (fromIntegral size)
    | otherwise = marked four 4 (fromIntegral size)
  where
    size = B.length bytes

counting :: Word8 -> Word8 -> Word8 -> Int -> ByteString
counting fixed two four count
    | count < 0x10 = B.singleton (fixed .|. fromIntegral count)
    | count <= 0xffff = marked two 2 (fromIntegral count)
    | otherwise = marked four 4 (fromIntegral count)

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
    | otherwise = Just (Bytes.bigEndian (B.take width bytes), B.drop width bytes)

array :: Int -> ByteString -> (Value, ByteString)
array count bytes = let (held, rest) = many count value bytes in (Array held, rest)

pairs :: Int -> ByteString -> (Value, ByteString)
pairs count bytes = let (held, rest) = many count pair bytes in (Map held, rest)
  where
    pair from = do
        (key, after) <- value from
        (held, rest) <- value after
        Just ((key, held), rest)

-- | A body that announces more than it holds yields what it held, and
-- the reader stops reading rather than stopping.
many :: Int -> (ByteString -> Maybe (a, ByteString)) -> ByteString -> ([a], ByteString)
many count read' bytes
    | count <= 0 = ([], bytes)
    | otherwise = case read' bytes of
        Nothing -> ([], bytes)
        Just (held, after) ->
            let (more, rest) = many (count - 1) read' after in (held : more, rest)
