{-# LANGUAGE StrictData #-}

module Reticulum.Rejection
    ( Rejection (..)
    ) where

data Rejection
    = -- | bytes present, bytes needed
      ShortHeader Int Int
    | -- | the count, the threshold
      HopLimit Int Int
    | -- | bytes present, bytes needed
      ShortPayload Int Int
    | -- | bytes present, the implicit length, the explicit length
      ProofLength Int Int Int
    | -- | bytes present, the length without signalling, and with it
      SignalledLength Int Int Int
    | -- | bytes needed
      ShortPlaintext Int
    | -- | bytes present, the one accepted length
      FixedLength Int Int
    deriving (Eq)
