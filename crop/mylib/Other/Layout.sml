structure Layout :> Layout =
struct
open General infix 2 $
open Pretty infix ^^ ++ \ & \\ &&

fun die s = raise Fail ("Layout: " ^ s)

datatype enumeration = Number | Letter | Roman | CapitalLetter | CapitalRoman

fun println n d = TextIO.println (pretty n d)

val chr = txt o str
val int = txt o Show.int
val real = txt o Show.real
val bool = txt o Show.bool
fun option f = txt o Show.option f

val spaces = txt o String.spaces

val lparen = txt "("
val rparen = txt ")"
val langle = txt "<"
val rangle = txt ">"
val lbrace = txt "{"
val rbrace = txt "}"
val lbracket = txt "["
val rbracket = txt "]"
val pling = txt "'"
val quote = txt "\""
val semi = txt ";"
val colon = txt ":"
val comma = txt ","
val space = txt " "
val dot = txt "."
val dash = txt "-"
val sharp = txt "#"
val percent = txt "%"
val dollar = txt "$"
val ampersand = txt "&"
val slash = txt "/"
val backslash = txt "\\"
val eq = txt "="
val tilde = txt "~"
val asterisk = txt "*"
val bar = txt "|"

fun punctuate sep ds =
    let
      fun loop nil = nil
        | loop [d] = [d]
        | loop (d :: ds) = (d ^^ sep) :: loop ds
    in
      loop ds
    end

fun column f = position (fn {column, ...} => f column)
fun row f = position (fn {row, ...} => f row)

fun align d = column (fn k => nesting (fn i => nest (k - i) d))
fun hang i d = align (nest i d)
fun indent i d = hang i (spaces i ^^ d)
fun width f d = column (fn l => d ^^ column (fn r => f (r - l)))
fun left f = column (fn c => max $ f o Option.map (fn m => m - c))

fun fill f =
    width (fn w =>
              if f > w then
                spaces (f - w)
              else
                empty
          )
fun fillBreak f =
    width (fn w =>
              if f >= w then
                spaces (f - w)
              else
                nest f brk
          )

val softln = group ln
val softbrk = group brk

local
  fun mk sep (l, r) = l ^^ sep ^^ r
in
val op++ = mk space
val op\  = mk ln
val op&  = mk softln
val op\\ = mk brk
val op&& = mk softbrk
end

local
  fun mk sep ds =
      case rev ds of
        nil     => empty
      | d :: ds => foldl sep d ds
in
val hsep = mk op++
val vsep = mk op\
val fsep = mk op&
val hcat = mk op^^
val vcat = mk op\\
val fcat = mk op&&
end

val sep = group o vsep
val cat = group o vcat

fun enclose (l, r) d = l ^^ d ^^ r
val plings   = enclose (pling, pling)
val quotes   = enclose (quote, quote)
val parens   = enclose (lparen, rparen)
val angles   = enclose (langle, rangle)
val braces   = enclose (lbrace, rbrace)
val brackets = enclose (lbracket, rbracket)

fun softtxt s =
    (fsep o
     map txt o
     String.fields Char.isSpace
    ) s
val paragraph = curry op^^ (spaces 2) o softtxt

fun str s =
    let
      datatype bullet = Text of string
                      | Numbered of string * int * string
(* TODO: We could really use a parser combinator library here. The code below
 * could be a starting point. Also review Parsec and the parser on JLouis' blog.
 *)
      fun bullet s =
          let
            fun or nil ss = NONE
              | or (r :: rs) ss =
                case r ss of
                  SOME x => SOME x
                | NONE   => or rs ss

            fun cat rs ss =
                let
                  fun loop (nil, ss) = SOME ("", ss)
                    | loop (r :: rs, ss) =
                      case r ss of
                        NONE => NONE
                      | SOME (s, ss) =>
                        case loop (rs, ss) of
                          NONE => NONE
                        | SOME (s', ss) => SOME (s ^ s', ss)
                in
                  loop (rs, ss)
                end

            val number = Int.scan StringCvt.DEC Substring.getc
            fun string s ss =
                let
                  fun loop (ss, nil) = SOME (s, ss)
                    | loop (ss, c :: cs) =
                      case Substring.getc ss of
                        SOME (c', ss') =>
                        if c' = c then
                          loop (ss', cs)
                        else
                          NONE
                      | NONE => NONE
                in
                  loop (ss, explode s)
                end
            fun ws ss =
                let
                  fun loop ss' =
                      case Substring.getc ss' of
                        SOME (c, ss') =>
                        if c = #" " then
                          case loop ss' of
                            SOME (s, ss') => SOME (" " ^ s, ss')
                          | NONE => SOME (" ", ss')
                        else
                          SOME ("", ss)
                      | NONE => NONE
                in
                  loop ss
                end
            val empty = string ""
            val AD = string "AD"
            val Ad = string "Ad"
            val ad = string "ad"
            val dot = string "."
            val colon = string ":"

            fun numbered ss =
                case cat [or [AD, Ad, ad, empty], ws] ss of
                  NONE => NONE
                | SOME (l, ss) =>
                  case number ss of
                    NONE => NONE
                  | SOME (n, ss) =>
                    case or [cat [ws, or [dot, colon]], empty] ss of
                      NONE => NONE
                    | SOME (r, ss) =>
                      SOME (Numbered (l, n, r), ss)

            fun text ss =
                case Substring.getc ss of
                  SOME (c, ss) =>
                  if c = #"o" orelse Char.isPunct c then
                    SOME (Text (String.str c), ss)
                  else
                    NONE
                | NONE => NONE
          in
            case or [numbered, text] s of
              SOME (b, s) => (SOME b, s)
            | NONE        => (NONE, s)
          end
      fun next (Text s) = Text s
        | next (Numbered (l, n, r)) = Numbered (l, n + 1, r)
      fun bulletToString b =
          case b of
            Text s => s
          | Numbered (l, n, r) => l ^ Int.toString n ^ r

      datatype t = Par of int * substring
                 | List of int * (string * t list) list

      fun trees ls =
          let
            fun loop (_, nil) = (nil, nil)
              | loop (i', ll as (i, l) :: ls) =
                if i' <= i then
                  case bullet l of
                    (NONE, _) =>
                    let
                      val (ts, ls) = loop (i', ls)
                    in
                      (Par (i - i', l) :: ts, ls)
                    end
                  | (SOME b, _) =>
                    let
                      fun loopi (_, _, nil) = (nil, nil)
                        | loopi (i'', b', ll as (i, l) :: ls) =
                          case (i'' = i, bullet l) of
                            (true, (SOME b, l)) =>
                            let
                              val b = if b = Text "." then next b' else b
                              val bs = bulletToString b
                              val (item, ls) = loop (i + size bs + 1, ls)
                              val (items, ls) = loopi (i, b, ls)
                            in
                              ((bs, Par (0, l) :: item) :: items, ls)
                            end
                          | _ => (nil, ll)
                      val (lst, ls) = loopi (i, b, ll)
                      val (ts, ls) = loop (i', ls)
                    in
                      (List (i - i', lst) :: ts, ls)
                    end
                else
                  (nil, ll)
            val (ts, _) = loop (0, ls)
          in
            ts
          end

      val softtxt = softtxt o Substring.string

      fun doc ts =
          let
            fun one (Par (i, s)) =
                spaces i ^^ nest i (softtxt s)
              | one (List (i, items)) =
                let
                  val width = foldl Int.max 0 (map (size o Pair.fst) items)
                in
                  vcat
                    (map
                       (fn (b, ts) =>
                           spaces i ^^ (fill width (txt b)) ^^
                                  nest (width + i + 1) (many ts)
                       ) items
                    )
                end
            and many ts = vcat (map one ts)
          in
            many ts
          end
    in
      doc o
      trees o
      map (Pair.map (Substring.size, id) o
           Substring.splitl Char.isSpace
          ) o
      Substring.fields (curry op= #"\n") $
      Substring.full s
    end

fun besides spc (l, r) =
    left
      (fn w =>
          let
            val w = Option.map (fn w => (w - spc) div 2) w
            val ls = linearize w l
            val rs = linearize w r
            val lw = foldl Int.max 0 $ map (fn (i, s) => i + size s) ls
            fun stitch (nil, (i, s) :: rs) =
                [spaces (lw + i + spc), txt s] :: stitch (nil, rs)
              | stitch ((i, s) :: ls, nil) =
                [spaces i, txt s] :: stitch (ls, nil)
              | stitch ((il, sl) :: ls, (ir, sr) :: rs) =
                [spaces il, txt sl, spaces (lw - il - size sl + spc),
                 spaces ir, txt sr] :: stitch (ls, rs)
              | stitch _ = nil
          in
            align o vcat o map hcat $ stitch (ls, rs)
          end
      )

fun flushRight d =
    left
      (fn NONE   => d
        | SOME w =>
          let
            val ls = linearize (SOME w) d
          in
            align o vcat $ map (fn (_, s) => spaces (w - size s) ^^ txt s) ls
          end
      )
fun itemize bullet ds =
    vcat $ map (curry op^^ (txt bullet ^^ space) o align) ds

local
  val number = Int.toString
  fun letter 1 = "a"
    | letter n =
      let
        val sigma = "abcdefghijklmnopqrstuvwxyz"
        val l = size sigma
        fun loop 0 = nil
          | loop n = String.sub (sigma, n mod l) :: loop (n div l)
      in
        implode o rev $ loop (n - 1)
      end
  local
    fun toChar x =
        case x of
          1000 => #"m"
        |  500 => #"d"
        |  100 => #"c"
        |   50 => #"l"
        |   10 => #"x"
        |    5 => #"v"
        |    1 => #"i"
        | _    => die "enumbullets.roman"
    fun toRoman x =
        let
          val rs = [1000, 500, 100, 50, 10, 5, 1]
          val rsr = rev rs
          fun subtract (x, y :: ys) =
              if x + y >= 0 then
                y
              else
                subtract (x, ys)
            | subtract _ = die "enumbullets.roman"

          fun loop (0, _) = nil
            | loop (x, yl as y :: ys) =
              if x >= y then
                y :: loop (x - y, yl)
              else
                (* Don't ask - it works *)
                if x >= y * (9 - y div hd ys mod 2) div 10 then
                  let
                    val z = subtract (x - y, rsr)
                  in
                    z :: y :: loop (x - y + z, ys)
                  end
                else
                  loop (x, ys)
            | loop _ = die "enumbullets.roman"
        in
          loop (x, rs)
        end
  in
  val roman = implode o map toChar o toRoman
  end
  fun enum style =
      case style of
        Number        => number
      | Letter        => letter
      | Roman         => roman
      | CapitalLetter => String.map Char.toUpper o letter
      | CapitalRoman  => String.map Char.toUpper o roman
in
fun enumerate (l, style, r) start ds =
    let
      val enum = enum style
      val start = Option.getOpt (start, 1)
      val bullets = List.tabulate
                      (length ds, fn n => l ^ enum (start + n) ^ r)
      val w = foldl Int.max 0 $ map size bullets
    in
      vcat o map (fn (b, s) => fill w $ txt b ++ align s)
                 $ ListPair.zip (bullets, ds)
    end
end

fun description items =
    vcat $ map (fn (s, d) => txt s ++ space ^^ nest 2 d) items

fun placeAt {row = r, column = c} doc =
    position (fn {row = r', column = c'} =>
                 if r' < r then
                   brk ^^ placeAt {row = r, column = c} doc
                 else if c' < c then
                   spaces (c - c') ^^ doc
                 else
                   doc
             )

end
