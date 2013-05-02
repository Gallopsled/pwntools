structure List :> List =
struct
open List
open General infixr 3 $ infix 4 \< \> infix 5 ^* to

local
  fun merge cmp (xs as x::xs') (ys as y::ys') zs =
      let
        val (a,b,c) = if cmp y x = LESS then (xs, ys', y) else (xs', ys, x)
      in merge cmp a b (c::zs) end
    | merge cmp xs ys zs = List.revAppend(zs, xs @ ys)

  fun mergeMany cmp   [] []   = []
    | mergeMany cmp [xs] []   = xs
    | mergeMany cmp   [] [ys] = ys
    | mergeMany cmp (a::b::xss) yss =
      mergeMany cmp xss ((merge cmp a b [])::yss)
    | mergeMany cmp xss yss = mergeMany cmp (xss @ yss) []
in
fun sort cmp lst = mergeMany cmp (map (fn x => [x]) lst) []
end


fun shuffle lst = let
  val seed = (Int.fromLarge o Time.toSeconds o Time.now) ()
  val gen  = Random.rand (seed, 101010)
  fun rnd_bool _ = Random.randRange (0,2) gen = 0
  fun shuffle'  [] tail = tail
    | shuffle' [x] tail = x::tail
    | shuffle'  xs tail =
      let
        val (left, right) = List.partition rnd_bool xs
        val right' = shuffle' right tail
      in shuffle' left right'
      end
in shuffle' lst [] end;


fun leftmost nil = NONE
  | leftmost (SOME x :: _) = SOME x
  | leftmost (NONE :: r) = leftmost r

fun rightmost xs = (leftmost o rev) xs

fun allPairs xs ys =
    List.concat (
    map (fn x => map (fn y => (x, y)) ys) xs
    )

fun splitAt x = (take x, drop x)

fun allSplits xs = tabulate (length xs, xs \< splitAt)

fun consAll (x, xss) = map (x \< op::) xss

fun concatMap f xs = foldr (fn (x, a) => f x @ a) nil xs

fun range m n = n \> take o m \> drop

fun power xs = foldl (fn (x, xs) => consAll (x, xs) @ xs) nil xs

(* fun group _ nil = nil *)
(*   | group eq (x :: xs) = *)
(*     let *)
(*       fun collect (y, ys, yss) = *)
(*           rev (y :: ys) :: yss *)
(*     in *)
(*       rev $ collect $ *)
(*           foldl *)
(*           (fn (x, a as (y, ys, yss)) => *)
(*               if eq x y then *)
(*                 (x, y :: ys, yss) *)
(*               else *)
(*                 (x, nil, collect a) *)
(*           ) *)
(*           (x, nil, nil) *)
(*           xs *)
(*     end *)

fun group _ nil = nil
  | group equiv (x :: xs) =
    let
      val (xs, ys) = List.partition (equiv x) xs
    in
      (x :: xs) :: group equiv ys
    end

fun transpose nil = nil
  | transpose [xs] =
    List.map (fn x => [x]) xs
  | transpose (xs :: xss) =
    map op:: $ ListPair.zip (xs, transpose xss)

fun loopl _ state nil = (nil, state)
  | loopl f state (x :: xs) =
    let
      val (x, state) = f (x, state)
      val (xs, state) = loopl f state xs
    in
      (x :: xs, state)
    end

fun loopr _ state nil = (nil, state)
  | loopr f state (x :: xs) =
    let
      val (xs, state) = loopr f state xs
      val (x, state) = f (x, state)
    in
      (x :: xs, state)
    end
end
