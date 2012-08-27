{-# LANGUAGE OverloadedStrings #-}
-- import Crypto.Crypto.RSA as RSA
import Codec.Crypto.RSA
import Crypto.Random (newGenIO, SystemRandom)
import System.Environment (getArgs)
import Numeric (readHex, showHex)
import Data.ByteString.Lazy (ByteString, pack, unpack)
import Data.ByteString.Lazy.Char8 ()
import qualified Data.ByteString.Lazy.Char8 as BT
import Crypto.Types.PubKey.RSA (public_size, public_n, public_e, private_d)

enhex = flip showHex ""
dehex = fst . head . readHex

lmodpad :: Int -> Char -> String -> String
lmodpad n c s | length s `mod` n == 0 = s
              | otherwise             = lmodpad n c (c : s)

hex :: Integer -> String
hex n = if even (length s) then s else '0' : s
    where s = showHex n ""

groupInto :: Int -> String -> [String]
groupInto n [] = []
groupInto n l  = h : groupInto n t
    where (h,t) = splitAt n l

prettySplit :: String -> String
prettySplit = ("0x" ++) . foldl1 (\a b -> a ++ ", 0x" ++ b) . reverse . groupInto 8 . lmodpad 8 '0'

main = do
  g <- newGenIO :: IO SystemRandom
  let (pub, pri, g') = generateKeyPair g 2048
  putStrLn "n:"
  putStrLn $ prettySplit $ hex $ public_n pub
  putStrLn "d:"
  putStrLn $ prettySplit $ hex $ private_d pri

