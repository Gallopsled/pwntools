{-# LANGUAGE MultiParamTypeClasses, ScopedTypeVariables #-}
module Main where

import Debug.Trace

import Prelude hiding (lookup, catch)
import Control.Exception (catch, SomeException)
import System.Environment
import System.IO.Unsafe

import qualified Data.Elf as Elf
import qualified Text.Disassembler.X86Disassembler as Disas
import Text.Disassembler.X86Disassembler hiding (bytes, opcode, address)
import qualified Data.ByteString as B

import Data.List (findIndex, isPrefixOf, isSuffixOf)
import Data.Either
import qualified Data.Map as M
import Data.Map (Map)
import Data.Word (Word8)
import Control.Monad.Identity
import Control.Monad.State
import Control.Monad.Writer

import Numeric

-- Gadget markers:
{- ret, ret far
   retn, retn far
   jmp eax, jmp ebx, jmp ecx, jmp edx, jmp edi, jmp esi, jmp ebp, jmp esi
   jmp [eax], ...
   jmp [eax + imm8], ...
   jmp [eax + 1mm16], ...
   jmp [eax + imm32], ...
   jmp [eax * imm + imm], ...
-}

markers =
  [ Marker "RET" [0xc3]
  , Marker "JMP" [0xff, 0xe0] -- EAX
  , Marker "JMP" [0xff, 0xe3] -- EBX
  , Marker "JMP" [0xff, 0xe1] -- ECX
  , Marker "JMP" [0xff, 0xe2] -- EDX
  , Marker "JMP" [0xff, 0xe7] -- EDI
  , Marker "JMP" [0xff, 0xe6] -- ESI
  , Marker "JMP" [0xff, 0xe5] -- EBP
  , Marker "JMP" [0xff, 0xe4] -- ESP
  , Marker "JMP" [0xff, 0x20] -- [EAX]
  , Marker "JMP" [0xff, 0x23] -- [EBX]
  , Marker "JMP" [0xff, 0x21] -- [ECX]
  , Marker "JMP" [0xff, 0x22] -- [EDX]
  , Marker "JMP" [0xff, 0x27] -- [EDI]
  , Marker "JMP" [0xff, 0x26] -- [ESI]
  , Marker "JMP" [0xff, 0x65, 0x00] -- [EBP]
  , Marker "JMP" [0xff, 0x24, 0x24] -- [ESP]
  , Marker "CALL" [0xff, 0xd0] -- EAX
  , Marker "CALL" [0xff, 0xd3] -- EBX
  , Marker "CALL" [0xff, 0xd1] -- ECX
  , Marker "CALL" [0xff, 0xd2] -- EDX
  , Marker "CALL" [0xff, 0xd7] -- EDI
  , Marker "CALL" [0xff, 0xd6] -- ESI
  , Marker "CALL" [0xff, 0xd5] -- EBP
  , Marker "CALL" [0xff, 0xd4] -- ESP
  ]

-- boring =
--   [ [[0xc9], [0xc3]] -- leave ; ret
--   , [[0x5d], [0xc3]] -- pop ebp ; ret
--   ]
boring = []

isExec s =
  Elf.SHF_EXECINSTR `elem` Elf.elfSectionFlags s

type Addr = Int

data POI =
  POI
  { bytes  :: B.ByteString
  , base   :: Addr
  , offset :: Int
  , marker :: Marker
  }
  deriving Show

data Marker =
  Marker
  { opcode   :: String
  , magic    :: [Word8]
  }
  deriving Show

data Gadget =
  Gadget
  { address :: Addr
  , code    :: [Instruction]
  }
  deriving Show

extractROI poi prelude =
  B.take (prelude + context) $
  B.drop (offset poi - prelude) $ bytes poi
    where
      context = 10

disasPOI poi prelude =
  runIdentity $ disassembleListWithConfig conf $
  B.unpack $ extractROI poi prelude
    where
      conf =
        defaultConfig
        { confIn64BitMode    = False
        , confStartAddr      = fromIntegral $ base poi + offset poi - prelude
        }

isRealInstructions = all isRealInstruction
  where
    isRealInstruction (Instruction _ _ _ _ _) = True
    isRealInstruction _ = False

extractGadget marker insts =
  if isRealInstructions insts
  -- if True
  then
    case (\idx -> take (idx + 1) insts) `fmap`
         findIndex (\inst -> magic marker == Disas.bytes inst) insts of
      r@(Just insts') ->
        if magic marker `isPrefixOf` Disas.bytes (last insts')
        then r
        else Nothing
      _ -> Nothing
  else Nothing

isBoring insts =
  if elem "-b" $ unsafePerformIO getArgs
  then False
  else any (\suf -> suf `isSuffixOf` map Disas.bytes insts) boring

findPOIs markers elf =
  concatMap (findPOIsInSection markers) secs
    where
      secs = filter isExec $ Elf.elfSections elf

findPOIsInSection markers sec =
  concatMap pois markers
    where
      bytes   = Elf.elfSectionData sec
      base    = fromIntegral $ Elf.elfSectionAddr sec
      pois marker =
        fmap (\poi -> POI bytes base poi marker) $ pois1 $ magic marker
      pois1 magic =
        filter (\ind -> B.isPrefixOf (B.pack magic) $ B.drop ind bytes) inds
          where
            inds = head magic `B.elemIndices` bytes

data Trie = Branch (Map [Word8] Trie)
          | Leaf Gadget
          deriving Show

empty = Branch M.empty

-- lookup (code : codes) (Branch tmap) =
--   do trie <- M.lookup code tmap
--      lookup codes trie
-- lookup [] (Leaf g) = Just g
-- lookup _ _ = Nothing

insert (code : codes) gadget (Branch tmap) =
  case M.lookup code tmap of
    Just innerTrie ->
      go $ insert codes gadget innerTrie
    Nothing ->
      go $ foldr (\c t -> Branch $ M.singleton c t) (Leaf gadget) codes
    where
      go trie = Branch $ M.insert code trie tmap

insert codes gadget (Leaf _) = insert codes gadget empty
insert _ _ t = t

toList (Branch tmap) = concatMap toList $ M.elems tmap
toList (Leaf g) = [g]

type Collect a = State Trie a
record gadget = do
  modify $ insert revCodes gadget
  where
    revCodes = reverse $ map Disas.bytes $ code gadget

goPOI' poi prelude =
  case disasPOI poi prelude of
    Left _ -> return ()
    Right insts ->
      case extractGadget (marker poi) insts of
        Just insts' ->
          unless (isBoring insts') $
          record $ Gadget (base poi + offset poi + prelude) insts'
        Nothing -> return ()

goPOI poi =
  sequence_ $ zipWith ($) (repeat $ goPOI' poi) [0..10]

go bytes =
  let pois = findPOIs markers $ Elf.parseElf bytes
      doit = mapM_ goPOI pois
  in toList $ execState doit empty

showGadget gadget = do
  putStrLn $ "  0x" ++ (flip showHex "" $ address gadget)
  mapM (putStrLn . show) $ code gadget
  putStrLn ""

main = do
  args <- getArgs
  name <- getProgName
  case args of
    file : _ -> do bytes <- B.readFile file
                   let x = go bytes
                   mapM_ (showGadget) x
    [] -> putStrLn $ "Usage: " ++ name ++ " <ELF file>"
