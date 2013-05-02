structure Pretty :> Pretty =
struct
open Lazy General
datatype t' =
         Empty
       | Join     of t * t
       | Line     of bool
       | Nest     of int * t
       | Text     of string
       | Choice   of t * t
       | Nesting  of int -> t
       | Printed  of int -> t
       | Position of {row: int, column: int} -> t
       | Max      of int option -> t
withtype t = t' Lazy.t
type line = int * string

val empty = eager Empty

val ln = eager (Line true)
val brk = eager (Line false)
val printed = eager o Printed
val position = eager o Position
val nesting = eager o Nesting
val max = eager o Max

infix ^^

val op^^ = eager o Join

fun txt str =
    case map (eager o Text) $ String.fields (#"\n" \< op=) str of
      nil => empty
    | l :: ls =>
      foldl (fn (l, doc) => doc ^^ brk ^^ l)
            l
            ls

fun nest n = eager o curry Nest n

fun flatten doc =
    delay
      (fn _ =>
          case force doc of
            Empty         => doc
          | Join (l, r)   => flatten l ^^ flatten r
          | Nest (i, doc) => nest i (flatten doc)
          | Text _        => doc
          | Line b        => if b then txt " " else empty
          | Choice (w, _) => w
          | Printed f     => printed (flatten o f)
          | Position f    => position (flatten o f)
          | Nesting f     => nesting (flatten o f)
          | Max f         => max (flatten o f)
      )

fun choice (w, n) =
    eager (Choice (flatten w, n))
fun group d = choice (d, d)

fun linearize max doc =
    let
      datatype t' =
               Nil
             | Print of string * t
             | Linefeed of int * t
      withtype t = t' Lazy.t

      fun lin doc =
          let
            fun loop (i, acc, doc) =
                case force doc of
                  Nil                => [(i, acc)]
                | Print (str, doc)   => loop (i, acc ^ str, doc)
                | Linefeed (i', doc) => (i, acc) :: loop (i', "", doc)
          in
            loop (0, "", doc)
          end

      fun fits col doc =
          case max of
            NONE   => true
          | SOME c => col <= c andalso
                      case force doc of
                        Print (str, doc) => fits (col + size str) doc
                      | _                => true

      (* prev is the total number of characters on all previous lines, including
       * new-lines
       *)
      fun moveCol {col, row, prev} n =
          {col = col + n, row = row, prev = prev}
      fun nextRow {col, row, prev} nest =
          {col = nest, row = row + 1, prev = prev + col + 1}
      fun col {col, ...} = col
      fun row {row, ...} = row
      fun total {col, prev, ...} = col + prev
      val initialState = {row = 0, col = 0, prev = 0}

      fun best st wl =
          delay
            (fn _ =>
                case wl of
                  nil => eager Nil
                | (nest, doc) :: rest =>
                  case force doc of
                    Empty         =>
                    best st rest
                  | Join (l, r)   =>
                    best st ((nest, l) :: (nest, r) :: rest)
                  | Nest (i, doc) =>
                    best st ((nest + i, doc) :: rest)
                  | Text str      =>
                    eager (Print (str, best (moveCol st $ size str) rest))
                  | Line _        =>
                    eager (Linefeed (nest, best (nextRow st nest) rest))
                  | Choice (w, n) =>
                    let
                      val w = best st ((nest, w) :: rest)
                    in
                      if fits (col st) w then
                        w
                      else
                        best st ((nest, n) :: rest)
                    end
                  | Printed f     =>
                    best st ((nest, f $ total st) :: rest)
                  | Position f      =>
                    best st ((nest, f {row = row st, column = col st})
                             :: rest)
                  | Nesting f     =>
                    best st ((nest, f nest) :: rest)
                  | Max f         =>
                    best st ((nest, f max) :: rest)
            )
    in
      lin (best initialState [(0, doc)])
    end

fun fold f s max doc = foldl f s (linearize max doc)

local
  fun strs nil = nil
    | strs ((_, "") :: ls) = "\n" :: strs ls
    | strs [(i, s)] = [String.spaces i, s]
    | strs ((i, s) :: ls) = String.spaces i :: s :: "\n" :: strs ls
in
fun pretty n d = String.concat (strs (linearize n d))
end
end
