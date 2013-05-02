structure LazyList :> LazyList =
struct
open General Lazy infix 2 $ infix 4 \< \> infix 5 ^* to
datatype 'a t' = Cons of 'a * 'a t
               | Nil
withtype 'a t = 'a t' Lazy.t

val F = force
val E = eager
val L = lazy

fun eager nil = E Nil
  | eager (x :: xs) = E $ Cons (x, eager xs)

fun force xs =
    case F xs of
      Cons (x, xs) => x :: force xs
    | Nil          => nil

fun split l =
    case F l of
      Cons x => SOME x
    | Nil    => NONE

fun consEager x = E $ Cons x

fun cons (x, xs) = L (fn _ => Cons (F x, xs))

fun singleton x = eager [x]

fun null l =
    case F l of
      Nil => true
    | _   => false

infixr 5 @
fun xs @ ys =
    L (fn _ =>
          case F xs of
            Cons (x, xs) => Cons (x, xs @ ys)
          | Nil          => F ys
      )

fun hd l =
    case F l of
      Cons (x, _) => x
    | Nil         => raise Empty

fun tl l =
    case F l of
      Cons (_, xs) => xs
    | Nil          => raise Empty

fun last l =
    let
      fun loop (x, l) =
          case F l of
            Cons x => loop x
          | Nil    => x
    in
      case F l of
        Cons x => loop x
      | Nil    => raise Empty
    end

val getItem = split

fun nth (l, n) = hd o tl ^* n $ l handle Empty => raise Subscript

fun take (l, n) =
    L (fn _ =>
          if n = 0 then
            Nil
          else
            case F l of
              Cons (x, xs) => Cons (x, take (xs, n - 1))
            | Nil          => raise Subscript
      )

fun drop (l, n) = tl ^* n $ l

fun rev l = (eager o List.rev o force) l

fun concat ls =
    L (fn _ =>
          case F ls of
            Cons (l, ls) => F $ l @ concat ls
          | Nil          => Nil
      )

fun revAppend _ = raise Fail "Lazy.List.revAppend unimplemented"

fun app f = List.app f o force

fun map f l =
    L (fn _ =>
          case F l of
            Cons (x, xs) => Cons (f x, map f xs)
          | Nil          => Nil
      )

fun mapPartial f l =
    L (fn _ =>
          case F l of
            Cons (x, xs) =>
            (case f x of
               SOME x => Cons (x, mapPartial f xs)
             | NONE   => F $ mapPartial f xs
            )
          | Nil          => Nil
      )

fun find p l =
    case F l of
      Cons (x, xs) =>
      if p x then
        SOME x
      else
        find p xs
    | Nil          => NONE

fun filter p l =
    L (fn _ =>
          case F l of
            Cons (x, xs) =>
            if p x then
              Cons (x, filter p xs)
            else
              F $ filter p xs
          | Nil          => Nil
      )

fun partition p l = (filter p l, filter (not o p) l)

fun foldl f b l =
    case F l of
      Cons (x, xs) => foldl f (f (x, b)) xs
    | Nil          => b

fun length l = foldl (fn (_, a) => 1 + a) 0 l

fun foldr f b = List.foldr f b o List.rev o force

fun exists p l =
    case F l of
      Cons (x, xs) => p x orelse exists p xs
    | Nil          => false

fun all p l =
    case F l of
      Cons (x, xs) => p x andalso all p xs
    | Nil          => true

fun tabulate (n, f) =
    let
      fun loop i =
          if i = n then
            E Nil
          else
            L (fn _ => Cons (f i, loop (i + 1)))
    in
      loop 0
    end

exception Stop
fun tabulateN f =
    let
      fun loop n =
          L (fn _ => Cons (f n, loop (n + 1))
                handle Stop => Nil
            )
    in
      loop 0
    end

fun collate cmp (xs, ys) =
    case (F xs, F ys) of
      (Cons (x, xs), Cons (y, ys)) =>
      (case cmp (x, y) of
         EQUAL => collate cmp (xs, ys)
       | x     => x
      )
    | (Cons _, Nil)                => GREATER
    | (Nil, Cons _)                => LESS
    | (Nil, Nil)                   => EQUAL

fun allPairs xs ys =
    E Nil

fun fromFile f =
    let
      val is = TextIO.openIn f
      fun loop _ =
          case TextIO.input1 is of
            SOME c => Cons (c, L loop)
          | NONE   => Nil before TextIO.closeIn is
    in
      L loop
    end

end
