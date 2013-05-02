

functor PairingHeapFn (Key : Ordered) :> Heap where type key = Key.t =
struct
open General infix 2 $ infix 4 \< \> infix 5 ^* to
type key = Key.t

datatype 'a t = E
              | T of key * 'a * 'a t list

val empty = E
fun isEmpty E = true
  | isEmpty _ = false

fun merge h E = h
  | merge E h = h
  | merge (h1 as T (k1, v1, hs1)) (h2 as T (k2, v2, hs2)) =
    case Key.compare k1 k2 of
      LESS => T (k1, v1, h2 :: hs1)
    | _    => T (k2, v2, h1 :: hs2)
fun insert h (k, v) = merge (T (k, v, nil)) h
val push = insert

fun fromList xs = foldl (flip $ uncurry insert) empty xs

fun peeki E = raise Empty
  | peeki (T (k, v, _)) = (k, v)
fun min E = raise Empty
  | min (T (k, v, _)) = v
val peek = min

local
  fun mergePairs nil = E
    | mergePairs [h] = h
    | mergePairs (h1 :: h2 :: hs) = merge (merge h1 h2) (mergePairs hs)
in
fun delete E = raise Empty
  | delete (T (_, _, hs)) = mergePairs hs
val pop = delete
end

fun split h = (min h, delete h)
fun spliti h = (peeki h, delete h)

fun insertList h = foldl (fn (x, h) => insert h x) h

fun map _ E = E
  | map f (T (k, v, hs)) = T (k, f v, List.map (map f) hs)

fun size E = 0
  | size (T (_, _, hs)) = 1 + foldl (fn (h, a) => size h + a) 0 hs

fun toListi E = nil
  | toListi h = peeki h :: toListi (delete h)
fun toList E = nil
  | toList h = min h :: toList (delete h)

fun toString h = raise Fail "PairingHeapFn.toString"
end
