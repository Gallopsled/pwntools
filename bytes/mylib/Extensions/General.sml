structure General :> General =
struct
open General
fun id x = x
fun const a b = a
fun flipc f a b = f b a
fun flip f (a, b) = f (b, a)
fun \< (a, f) b = f (a, b)
fun \> (b, f) a = f (a, b)

fun $ (f, v) = f v

fun ^* (_, 0) = id
  | ^* (f, n) = f o (^* (f, n - 1))

fun curry f a b = f (a, b)
fun uncurry f (a, b) = f a b
fun pair a b = (a, b)

fun curry3 f a b c = f (a, b, c)
fun uncurry3 f (a, b, c) = f a b c
fun triple a b c = (a, b, c)

fun curry4 f a b c d = f (a, b, c, d)
fun uncurry4 f (a, b, c, d) = f a b c d
fun quadruple a b c d = (a, b, c, d)

fun to (a, b) =
    if a <= b then
      a :: to (a + 1, b)
    else
      nil

fun inc x = (x := !x + 1 ; !x)
fun dec x = (x := !x - 1 ; !x)
end
