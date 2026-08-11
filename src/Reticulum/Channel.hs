{-# LANGUAGE StrictData #-}

module Reticulum.Channel
    ( Envelope (..)
    , envelope
    , envelopeSize
    ) where

import Data.Bits (shiftL, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word (Word16)
import Prelude hiding (sequence)

import Reticulum.Packet (Rejection (ShortPlaintext))

envelopeSize :: Int
envelopeSize = 6

-- | The declared length is written and never read, so a message that
-- disagrees with it is delivered whole.
data Envelope = Envelope
    { messageType :: Word16
    , sequence :: Word16
    , declaredLength :: Word16
    , message :: ByteString
    }

envelope :: ByteString -> Either Rejection Envelope
envelope plain
    | B.length plain < envelopeSize = Left (ShortPlaintext envelopeSize)
    | otherwise =
        Right
            Envelope
                { messageType = word16 0
                , sequence = word16 2
                , declaredLength = word16 4
                , message = B.drop envelopeSize plain
                }
  where
    word16 at =
        B.foldl' (\value byte -> (value `shiftL` 8) .|. fromIntegral byte) 0 (B.take 2 (B.drop at plain))
