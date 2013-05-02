structure Pair :> Pair =
struct
type ('a, 'b) t = 'a * 'b

fun swap (a, b) = (b, a)
fun swizzle ((a, b), (c, d)) = ((a, c), (b, d))
fun fst (a, _) = a
fun snd (_, b) = b
fun app (fa, fb) (a, b) = (fa a ; fb b)
fun appFst f = f o fst
fun appSnd f = f o snd
fun map (fa, fb) (a, b) = (fa a, fb b)
fun mapFst f = map (f, General.id)
fun mapSnd f = map (General.id, f)
fun foldl (fa, fb) c (a, b) = fb (b, fa (a, c))
fun foldr (fa, fb) c (a, b) = fa (a, fb (b, c))
fun delay (ta, tb) = Lazy.lazy (fn _ => (Lazy.force ta, Lazy.force tb))
end
