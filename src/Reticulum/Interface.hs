{-# LANGUAGE StrictData #-}

module Reticulum.Interface
    ( Access (..)
    , access
    , Frame (..)
    , frame
    , pack
    , codeFor
    , minimumSize
    ) where

import Data.Bits (xor, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Maybe (catMaybes)
import Data.Word (Word8)

import qualified Reticulum.Encryption as Encryption
import qualified Reticulum.Identity as Identity

minimumSize :: Int
minimumSize = 1

salt :: ByteString
salt =
    B.pack
        [ 0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80
        , 0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a
        , 0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f
        , 0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8
        ]

data Access = Access
    { origin :: ByteString
    , key :: ByteString
    }

-- | Either half may be left out, and an interface told neither has no
-- access code at all.
access :: Maybe ByteString -> Maybe ByteString -> Maybe Access
access netname netkey
    | null halves = Nothing
    | otherwise = Just (Access material derived)
  where
    halves = catMaybes [netname, netkey]
    material = B.concat (map Identity.fullHash halves)
    derived =
        Encryption.derive Identity.keySize (Identity.fullHash material) salt

data Frame = Frame
    { code :: ByteString
    , packet :: ByteString
    }

frame :: Access -> Int -> ByteString -> Maybe Frame
frame held size raw
    | B.length raw <= 2 + size = Nothing
    | otherwise = Just (Frame carried recovered)
  where
    carried = B.take size (B.drop 2 raw)
    unmasked = mask held carried raw
    recovered = case B.unpack (B.take 2 unmasked) of
        [flags, hops] -> B.pack [flags .&. 0x7f, hops] <> B.drop (2 + size) unmasked
        _ -> B.empty

pack :: Access -> Frame -> Maybe ByteString
pack held value = case B.unpack (B.take 2 (packet value)) of
    [flags, hops] -> Just (announced (mask held (code value) carried))
      where
        carried =
            B.pack [flags .|. ifacFlag, hops] <> code value <> B.drop 2 (packet value)
    _ -> Nothing
  where
    announced masked = case B.uncons masked of
        Just (flags, rest) -> B.cons (flags .|. ifacFlag) rest
        Nothing -> masked

-- | The flag says the frame carries a code, and it survives the mask
-- because it is set again after it.
ifacFlag :: Word8
ifacFlag = 0x80

-- | The access code keys the mask and is the one run of bytes it is not
-- applied to.
mask :: Access -> ByteString -> ByteString -> ByteString
mask held carried raw =
    B.pack
        [ if at <= 1 || at > size + 1 then byte `xor` keyed else byte
        | (at, byte, keyed) <- zip3 [0 :: Int ..] (B.unpack raw) (B.unpack keyed')
        ]
  where
    size = B.length carried
    keyed' = Encryption.derive (B.length raw) carried (key held)

codeFor :: Access -> Int -> ByteString -> Maybe ByteString
codeFor held size message = case Identity.privateKey (key held) of
    Left _ -> Nothing
    Right private -> either (const Nothing) (Just . ending) (Identity.sign private message)
  where
    ending signature = B.drop (B.length signature - size) signature
