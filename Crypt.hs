import qualified Crypto.Cipher.AES as AES
import qualified Crypto.PBKDF2 as PBKDF2
import qualified Data.HMAC as HMAC
import qualified Data.Binary.Put as BinP
import qualified Data.Binary.Get as BinG
import qualified Data.Digest.SHA512 as SHA512
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LBC
import Data.Monoid((<>))
import Control.Applicative(liftA2, (<$>))
import Data.Word(Word64)
import qualified System.Random.MWC as R
import System.Environment(getArgs)
import System.IO(hPutStr,hFlush,stdin,stderr,hPutChar,hSetEcho)
import Control.Exception(bracket_)

aesBlockSize :: Int
aesBlockSize = 16

-- IV and salt need to be unique for each encryption key
-- 64 bits is enough to serve many different keys.
type Seed = Word64

type IVSeed = Seed
type SaltSeed = Seed

-- getIV takes a number (unique for each encryption key) and returns a 16 bytes IV
-- The 16 bytes IV returned is a concatanation of two identical 8 byte strings.
-- It does not really matter whether the entropy is halved to 8 bytes, 8 bytes is still plenty to make collisions extremely unlikely.
getIV :: IVSeed -> BS.ByteString
getIV n = LBS.toStrict $ p <> p
  where p = dumpsNumber n 

-- getSalt takes a number (unique for each encryption key) and returns a 8 byte salt
getSalt :: SaltSeed -> BS.ByteString
getSalt = LBS.toStrict . dumpsNumber

dumpsNumber :: Word64 -> LBS.ByteString
dumpsNumber = BinP.runPut . dumpsNumber'

dumpsNumber' :: Word64 -> BinP.Put
dumpsNumber' = BinP.putWord64le

loadsNumber' :: BinG.Get Word64
loadsNumber' = BinG.getWord64le

-- keySize needs to be 16, 24 or 32 bytes.
keySize :: Integer
keySize = 16 -- 128 bits

-- header will be prepended to the message before encryption.
-- used to check it decryption is valid.
header :: LBS.ByteString
header = LBC.pack "arbitrary"

-- encrypt/decrypt defaultChunkSize bytes at a time using the external interface (must be a multiple of the aes blocksize 16)
defaultChunkSize :: Int
defaultChunkSize = 32*k where k = 1024

stretchKey :: BS.ByteString -> BS.ByteString -> BS.ByteString
stretchKey key salt = let PBKDF2.HashedPass pass = pbkdf2 (PBKDF2.Password $ BS.unpack key) (PBKDF2.Salt $ BS.unpack salt)
                      in BS.pack pass
  where hashOutputSize = 64 -- sha512 returns a 64 bytes hash
        sha512_hm = HMAC.HashMethod SHA512.hash 1024 -- 1024: input block size of SHA-512
        hmacSpec = (HMAC.hmac sha512_hm, hashOutputSize)
        pbkdf2Rounds = 5000
        pbkdf2 = PBKDF2.pbkdf2' hmacSpec pbkdf2Rounds keySize

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
pad xs = xs <> BS.replicate fillNumber (fromIntegral fillNumber)
  where fillNumber = aesBlockSize - BS.length xs `rem` aesBlockSize

unpad :: BS.ByteString -> BS.ByteString
unpad xs = BS.take (BS.length xs - fromIntegral fillNumber) xs
  where fillNumber = BS.last xs
                      
encrypt :: BS.ByteString -> IVSeed -> SaltSeed -> LBS.ByteString -> LBS.ByteString
encrypt key ivSeed saltSeed msg = BinP.runPut $ do
  dumpsNumber' ivSeed
  dumpsNumber' saltSeed
  let msgWithHeader = header <> msg
  BinP.putLazyByteString $ encryptStream key ivSeed saltSeed $ chunks defaultChunkSize msgWithHeader

decrypt :: BS.ByteString -> LBS.ByteString -> Maybe LBS.ByteString
decrypt key msg = let Right (rest, _, (ivSeed, saltSeed)) = BinG.runGetOrFail (liftA2 (,) loadsNumber' loadsNumber') msg
                      decrypted = decryptStream key ivSeed saltSeed $ chunks defaultChunkSize rest
                      (header', decrypted') = LBS.splitAt (LBS.length header) decrypted
                  in if header /= header'
                     then Nothing
                     else Just decrypted'

encryptStream :: BS.ByteString -> IVSeed -> SaltSeed -> [BS.ByteString] -> LBS.ByteString
encryptStream key ivSeed saltSeed msgs = LBS.fromChunks $ encryptStream' (AES.initKey $ stretchKey key $ getSalt saltSeed) (getIV ivSeed) $ modifyLast pad msgs
  where encryptStream' _ _ [] = []
        encryptStream' key' iv (m:ms) = let enc = AES.encryptCBC key' (AES.IV iv) m
                                        in enc : encryptStream' key' (lastBlock enc) ms
          where lastBlock enc = BS.drop (BS.length enc - aesBlockSize) enc

decryptStream :: BS.ByteString -> IVSeed -> SaltSeed -> [BS.ByteString] -> LBS.ByteString
decryptStream key ivSeed saltSeed msgs = LBS.fromChunks $ modifyLast unpad $ decryptStream' (AES.initKey $ stretchKey key $ getSalt saltSeed) (getIV ivSeed) msgs
  where decryptStream' _ _ [] = []
        decryptStream' key' iv (m:ms) = let dec = AES.decryptCBC key' (AES.IV iv) m
                                        in dec : decryptStream' key' (lastBlock m) ms
          where lastBlock enc = BS.drop (BS.length enc - aesBlockSize) enc

main :: IO ()
main = do
  (mode:file:[]) <- getArgs
  case mode of
    "encrypt" -> do (ivSeed, saltSeed) <- getRandomPair
                    key <- getKey
                    interactFile file $ encrypt (BC.pack key) ivSeed saltSeed
    "decrypt" -> do key <- getKey
                    interactFile file $ maybe (error "decryption failed") id . decrypt (BC.pack key)
    _ -> error "error: encrypt|decrypt"
  where
    getKey = do
      hPutStr stderr "Key: "
      hFlush stderr
      pass <- bracket_ (hSetEcho stdin False) (hSetEcho stdin True) getLine
      hPutChar stderr '\n'
      return pass
    interactFile file transformer = transformer <$> LBS.readFile file >>= LBS.putStr
    getRandomPair = R.withSystemRandom . R.asGenIO $ \gen -> liftA2 (,) (R.uniform gen) (R.uniform gen)
