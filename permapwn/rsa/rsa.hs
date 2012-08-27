import Numeric
import System.Random

large :: IO Integer
large = randomRIO (0, 2^2048)

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

main = do n1 <- large
          n2 <- large
          putStrLn . prettySplit $ hex n1
          putStrLn . prettySplit $ hex n2
          putStrLn . prettySplit $ hex (n1 * n2)
