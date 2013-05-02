structure String :> String =
struct
open String
val tabulate = CharVector.tabulate

val TAB_WIDTH = ref 4

fun spaces n = tabulate (n, fn _ => #" ")

fun intercalate s ss =
    let
      fun loop (s' :: (ss as _ :: _)) = s' :: s :: loop ss
        | loop x = x
    in
      concat (loop ss)
    end

fun wordwrap width text =
    let
      fun line (n, nil) = (nil, nil)
        | line (n, w :: ws) =
          if Int.<= (n + 1 + Substring.size w, width) then
            let
              val (ws, ws') = line (n + 1 + Substring.size w, ws)
            in
              (w :: ws, ws')
            end
          else
            (nil, w :: ws)
      fun lines nil = nil
        | lines ws =
          let
            val (ln, ws) = line (0, ws)
          in
            ln :: lines ws
          end
    in
      (String.concatWith "\n" o
       List.map (Substring.concatWith " ") o
       List.concat o
       List.map lines o
       List.map (Substring.fields (General.curry op= #" ")) o
       Substring.fields (General.curry op= #"\n") o
       Substring.full) text
    end

fun untabify tabw = translate (fn #"\t" => spaces tabw | s => str s)

fun <- (s, x) =
    let
      open Substring
      val ss = full s
      fun loop i =
          if sub (ss, i) = #"%" then
            i
          else
            loop (i + 1)
      val i = loop 0
    in
      concat [slice (ss, 0, SOME i), full x, slice (ss, i + 1, NONE)]
    end handle Subscript => s
end
