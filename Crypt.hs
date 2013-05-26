import Crypto.Cipher.AES
import Crypto.PBKDF2
import qualified Data.HMAC as HMAC
import qualified Data.Binary.Put as BinP
import qualified Data.Binary.Get as BinG
import qualified Data.Digest.SHA512 as SHA512
import qualified Data.Digest.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LBC
import qualified Data.ByteString.Lazy.Internal as LBSI
import Control.Applicative(liftA2)
import Data.Word(Word64)
import qualified System.Random.MWC as R
import System.Environment(getArgs)

aesBlockSize :: Int
aesBlockSize = 16

-- getIV takes a number (unique for each encryption key) and returns a 16 byte IV
getIV :: Word64 -> BS.ByteString
getIV n = BS.take aesBlockSize $ BS.pack $ SHA256.hash $ LBS.unpack $ dumpsNumber n

-- getSalt takes a number (unique for each encryption key) and returns a 8 byte salt
-- salt has to be unique per encryption key - 64bit salt can serve many different passwords
getSalt :: Word64 -> BS.ByteString
getSalt = LBS.toStrict . dumpsNumber

dumpsNumber :: Word64 -> LBS.ByteString
dumpsNumber = BinP.runPut . dumpsNumber'

dumpsNumber' :: Word64 -> BinP.Put
dumpsNumber' = BinP.putWord64be

loadsNumber' :: BinG.Get Word64
loadsNumber' = BinG.getWord64be

-- keySize needs to be 16, 24 or 32 bytes.
keySize :: Integer
keySize = 16 -- 128 bits

-- header will be prepended to the message before encryption.
-- used to check it decryption is valid.
header :: LBS.ByteString
header = LBC.pack "arbitrary"

-- encrypt/decrypt defaultChunkSize bytes at a time using the external interface (must be a multiple of the aes blocksize 16)
defaultChunkSize :: Int
defaultChunkSize = LBSI.defaultChunkSize

stretchKey :: BS.ByteString -> BS.ByteString -> BS.ByteString
stretchKey key salt = let HashedPass pass = pbkdf2' (HMAC.hmac sha512_hm, hashOutputSize) pbkdf2Rounds keySize (Password $ BS.unpack key) (Salt $ BS.unpack salt)
                      in BS.pack pass
  where hashOutputSize = 64 -- sha512 returns a 64 bytes hash
        pbkdf2Rounds = 5000
        sha512_hm = HMAC.HashMethod SHA512.hash 1024 -- 1024: input block size of SHA-512

chunks :: Int -> LBS.ByteString -> [BS.ByteString]
chunks chunkSize str | LBS.null str = []
                     | otherwise = let (before, after) = LBS.splitAt (fromIntegral chunkSize) str
                                   in (LBS.toStrict before) : chunks chunkSize after

modifyLast :: (a -> a) -> [a] -> [a]
modifyLast _ [] = []
modifyLast f (x:[]) = [f x]
modifyLast f (x:xs) = x : modifyLast f xs

-- takes a string of arbitrary size and pads it to be divisible by 16 (aes block size) using PKCS#5 padding.
pad :: BS.ByteString -> BS.ByteString
pad xs = BS.append xs $ BS.replicate fillNumber (fromIntegral fillNumber)
  where fillNumber = aesBlockSize - BS.length xs `rem` aesBlockSize

unpad :: BS.ByteString -> BS.ByteString
unpad xs = BS.take (BS.length xs - fromIntegral fillNumber) xs
  where fillNumber = BS.last xs
                      
encrypt :: BS.ByteString -> Word64 -> Word64 -> LBS.ByteString -> LBS.ByteString
encrypt key ivSeed saltSeed msg = BinP.runPut $ do
  dumpsNumber' ivSeed
  dumpsNumber' saltSeed
  let msgWithHeader = header `LBS.append` msg
  BinP.putLazyByteString $ encryptStream key ivSeed saltSeed $ chunks defaultChunkSize msgWithHeader

decrypt :: BS.ByteString -> LBS.ByteString -> Maybe LBS.ByteString
decrypt key msg = let Right (rest, _, (ivSeed, saltSeed)) = BinG.runGetOrFail (liftA2 (,) loadsNumber' loadsNumber') msg
                      decrypted = decryptStream key ivSeed saltSeed $ chunks defaultChunkSize rest
                      (header', decrypted') = LBS.splitAt (LBS.length header) decrypted
                  in if header /= header'
                     then Nothing
                     else Just decrypted'

encryptStream :: BS.ByteString -> Word64 -> Word64 -> [BS.ByteString] -> LBS.ByteString
encryptStream key ivSeed saltSeed msgs = LBS.fromChunks $ encryptStream' (initKey $ stretchKey key $ getSalt saltSeed) (getIV ivSeed) $ modifyLast pad msgs
  where encryptStream' _ _ [] = []
        encryptStream' key' iv (m:ms) = let enc = encryptCBC key' (IV iv) m
                                        in enc : encryptStream' key' (lastBlock enc) ms
          where lastBlock enc = BS.drop (BS.length enc - aesBlockSize) enc

decryptStream :: BS.ByteString -> Word64 -> Word64 -> [BS.ByteString] -> LBS.ByteString
decryptStream key ivSeed saltSeed msgs = LBS.fromChunks $ modifyLast unpad $ decryptStream' (initKey $ stretchKey key $ getSalt saltSeed) (getIV ivSeed) msgs
  where decryptStream' _ _ [] = []
        decryptStream' key' iv (m:ms) = let dec = decryptCBC key' (IV iv) m
                                        in dec : decryptStream' key' (lastBlock m) ms
          where lastBlock enc = BS.drop (BS.length enc - aesBlockSize) enc

main :: IO ()
main = do
  (mode:key:[]) <- getArgs
  case mode of
    "encrypt" -> do (ivSeed, saltSeed) <- R.withSystemRandom . R.asGenIO $ \gen -> liftA2 (,) (R.uniform gen) (R.uniform gen) 
                    LBS.interact $ encrypt (BC.pack key) ivSeed saltSeed
    "decrypt" -> LBS.interact $ maybe (error "decryption failed") id . decrypt (BC.pack key)
    _ -> error "error: encrypt|decrypt"
  
