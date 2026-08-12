{-# LANGUAGE StrictData #-}

module Reticulum.Proof
    ( Proof (..)
    , proof
    , pack
    , hashMatch
    , proofDestination
    , signatureValid
    , implicitLength
    , explicitLength
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Maybe (fromMaybe)

import qualified Reticulum.Identity as Identity
import Reticulum.Packet (Rejection (ProofLength), addressLength)

implicitLength :: Int
implicitLength = Identity.signatureLength

explicitLength :: Int
explicitLength = 32 + Identity.signatureLength

data Proof = Proof
    { provedHash :: Maybe ByteString
    , signature :: ByteString
    }

proof :: ByteString -> Either Rejection Proof
proof payload
    | length' == implicitLength = Right (Proof Nothing payload)
    | length' == explicitLength =
        Right (Proof (Just (B.take 32 payload)) (B.drop 32 payload))
    | otherwise = Left (ProofLength length' implicitLength explicitLength)
  where
    length' = B.length payload

pack :: Proof -> ByteString
pack value = fromMaybe B.empty (provedHash value) <> signature value

-- | The explicit form carries a hash the receiver already computed, and
-- a decoder that trusts it accepts a proof for a packet it never sent.
hashMatch :: ByteString -> Proof -> Bool
hashMatch computed = maybe True (computed ==) . provedHash

proofDestination :: ByteString -> ByteString
proofDestination = B.take addressLength

signatureValid :: ByteString -> ByteString -> Proof -> Bool
signatureValid key computed value = Identity.verify key computed (signature value)
