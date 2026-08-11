{-# LANGUAGE StrictData #-}

module Reticulum.Interface.Hdlc
    ( framed
    , frames
    ) where

import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word (Word8)

flag :: Word8
flag = 0x7e

escape :: Word8
escape = 0x7d

escapeMask :: Word8
escapeMask = 0x20

framed :: ByteString -> ByteString
framed body = B.concat [B.singleton flag, escaped body, B.singleton flag]
  where
    escaped =
        replaced (B.singleton flag) (B.pack [escape, flag `xor` escapeMask])
            . replaced (B.singleton escape) (B.pack [escape, escape `xor` escapeMask])

-- | The closing flag stays in the buffer as the next frame's opening
-- one, and a run that reaches the limit without one is abandoned.
frames :: Int -> ByteString -> ([ByteString], ByteString)
frames limit = go []
  where
    go done buffer = case B.elemIndex flag buffer of
        Nothing -> (reverse done, B.empty)
        Just start -> case B.elemIndex flag body of
            Nothing
                | B.length buffer > limit -> (reverse done, B.empty)
                | otherwise -> (reverse done, buffer)
            Just end -> go (kept (unescaped (B.take end body)) done) (B.drop (start + 1 + end) buffer)
          where
            body = B.drop (start + 1) buffer

    kept frame done
        | B.null frame = done
        | otherwise = frame : done

-- | Two passes over the whole frame rather than a walk of it, and the
-- flag pass runs first, so what an escaped escape leaves behind is read
-- again by the pass after it.
unescaped :: ByteString -> ByteString
unescaped =
    replaced (B.pack [escape, escape `xor` escapeMask]) (B.singleton escape)
        . replaced (B.pack [escape, flag `xor` escapeMask]) (B.singleton flag)

replaced :: ByteString -> ByteString -> ByteString -> ByteString
replaced from to subject
    | B.null rest = subject
    | otherwise = B.concat [before, to, replaced from to (B.drop (B.length from) rest)]
  where
    (before, rest) = B.breakSubstring from subject
