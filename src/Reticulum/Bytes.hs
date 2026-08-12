module Reticulum.Bytes
    ( bigEndian
    , bigEndianOf
    ) where

import Data.Bits (shiftL, shiftR, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word (Word64)

bigEndian :: ByteString -> Word64
bigEndian = B.foldl' (\held byte -> (held `shiftL` 8) .|. fromIntegral byte) 0

bigEndianOf :: Int -> Word64 -> ByteString
bigEndianOf width count =
    B.pack [fromIntegral (count `shiftR` (8 * place)) | place <- [width - 1, width - 2 .. 0]]
