structure ListMap :> Map =
struct
open General infix 2 $ infix 4 \< \> infix 5 ^* to
val fst = Pair.fst val snd = Pair.snd
fun unimp _ = raise Fail "ListMap: Unimplemented"

type (''a, 'b) t = (''a * 'b) list

val empty = nil

fun singleton x = [x]

val size = length

fun domain m = map fst m

fun inDomain m k = List.exists (k \< op=) $ domain m

fun update m (k, v) =
    if inDomain m k then
      m
    else
      (k, v) :: m

fun insert m (k, v) =
    if inDomain m k then
      NONE
    else
      SOME $ (k, v) :: m

fun delete m k = List.filter (k \< op<> o fst) m

fun lookup m k = Option.map snd $ List.find (k \< op= o fst) m


val fromList = unimp
val remove = unimp
val modify = unimp
val isEmpty = unimp
val toList = unimp
val domain = unimp
val range = unimp
val split = unimp
val collate = unimp
val partition = unimp
val partitioni = unimp
val filter = unimp
val filteri = unimp
val exists = unimp
val existsi = unimp
val all = unimp
val alli = unimp
val find = unimp
val findi = unimp
val app = unimp
val appi = unimp
val map = unimp
val mapi = unimp
val fold = unimp
val foldi = unimp
val union = unimp
val unioni = unimp
val inter = unimp
val interi = unimp
val merge = unimp
val mergei = unimp
val plus = unimp
end
