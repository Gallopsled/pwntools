structure Either :> Either =
struct
datatype ('a, 'b) t = Left of 'a | Right of 'b
exception Either

fun ofLeft (Left x) = x
  | ofLeft _ = raise Either

fun ofRight (Right x) = x
  | ofRight _ = raise Either

fun either l r e =
    case e of
      Left x  => l x
    | Right x => r x

fun lefts es = List.mapPartial (fn Left x => SOME x | _ => NONE) es
fun rights es = List.mapPartial (fn Right x => SOME x | _ => NONE) es

fun partition es = (lefts es, rights es)
end
