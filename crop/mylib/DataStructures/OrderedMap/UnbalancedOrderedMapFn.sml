functor UnbalancedOrderedMapFn (Key : Ordered) :> OrderedMap where type key = Key.t =
struct
fun die s = raise Fail ("UnbalancedOrderedMapFn: " ^ s ^ " is unimplemented")

type key = Key.t

datatype 'a t = E
              | T of 'a t * (key * 'a) * 'a t

val empty = E

fun singleton x = T (E, x, E)

fun insert E x = SOME (singleton x)
  | insert (T (l, y as (k', _), r)) (x as (k, _)) =
    case Key.compare k k' of
      GREATER =>
      (case insert r x of
         SOME r' => SOME (T (l, y, r'))
       | NONE => NONE)
    | LESS    =>
      (case insert l x of
         SOME l' => SOME (T (l', y, r))
       | NONE => NONE)
    | EQUAL   => NONE

fun update E x = singleton x
  | update (t as T (l, y as (k', _), r)) (x as (k, _)) =
    case Key.compare k k' of
      GREATER => T (l, y, update r x)
    | LESS    => T (update l x, y, r)
    | EQUAL   => T (l, x ,r)

fun fromList xs = foldl (fn (x, t) => update t x) empty xs

fun splitFirst E = raise Empty
  | splitFirst (T (E, x, r)) = (x, r)
  | splitFirst (T (l, x, r)) =
    let
      val (y, l') = splitFirst l
    in
      (y, T (l', x, r))
    end

fun splitLast E = raise Empty
  | splitLast (T (l, x, E)) = (x, l)
  | splitLast (T (l, x, r)) =
    let
      val (y, r') = splitLast r
    in
      (y, T (l, x, r'))
    end

(* Crude balancing *)
val goLeft = ref true
fun split t = if (!goLeft before goLeft := not (!goLeft)) then
                splitFirst t
              else
                splitLast t

fun delete E _ = E
  | delete (T (l, y as (k', _), r)) k =
    case Key.compare k k' of
      GREATER => T (l, y, delete r k)
    | LESS    => T (delete l k, y, r)
    | EQUAL   =>
      let
        val (y', r') = splitFirst r
      in
        T (l, y', r')
      end

fun remove E _ = raise Domain
  | remove (T (l, y as (k', v'), r)) k =
    case Key.compare k k' of
      GREATER =>
      let
        val (v, r') = remove r k
      in
        (v, T (l, y, r'))
      end
    | LESS    =>
      let
        val (v, l') = remove l k
      in
        (v, T (l', y, r))
      end
    | EQUAL   =>
      let
        val (y', r') = splitFirst r
      in
        (v', T (l, y', r'))
      end

fun modify f E _ = raise Domain
  | modify f (T (l, y as (k', v'), r)) k =
    case Key.compare k k' of
      GREATER => T (l, y, modify f r k)
    | LESS    => T (modify f l k, y, r)
    | EQUAL   => T (l, (k', f v'), r)

fun lookup E _ = NONE
  | lookup (T (l, y as (k', v'), r)) k =
    case Key.compare k k' of
      GREATER => lookup r k
    | LESS    => lookup l k
    | EQUAL   => SOME v'

fun inDomain E _ = false
  | inDomain (T (l, y as (k', _), r)) k =
    case Key.compare k k' of
      GREATER => inDomain r k
    | LESS    => inDomain l k
    | EQUAL   => true

fun isEmpty E = true
  | isEmpty _ = false

fun size E = 0
  | size (T (l, _, r)) = 1 + size l + size r

fun toList E = nil
  | toList (T (l, x, r)) = toList l @ x :: toList r

fun domain E = nil
  | domain (T (l, (k, _), r)) = domain l @ k :: domain r

fun range E = nil
  | range (T (l, (_, v), r)) = range l @ v :: range r

fun first E = raise Empty
  | first (T (E, (_, v), _)) = v
  | first (T (l, _, _)) = first l
fun firsti E = raise Empty
  | firsti (T (E, x, _)) = x
  | firsti (T (l, _, _)) = firsti l

fun last E = raise Empty
  | last (T (_, (_, v), E)) = v
  | last (T (_, _, r)) = last r
fun lasti E = raise Empty
  | lasti (T (_, x, E)) = x
  | lasti (T (_, _, r)) = lasti r

fun collate _ = die "collate"
fun partition _ = die "partition"
fun partitioni _ = die "partitioni"
fun filter _ = die "filter"
fun filteri _ = die "filteri"
fun exists _ = die "exists"
fun existsi _ = die "existsi"

fun all _ E = true
  | all p (T (l, (_, v), r)) =
    p v andalso all p l andalso all p r

fun alli _ E = true
  | alli p (T (l, (k, v), r)) =
    p (k, v) andalso alli p l andalso alli p r

fun find _ = die "find"
fun findi _ = die "findi"
fun app _ E = ()
  | app f (T (l, (k, v), r)) =
    (app f l ; f v ; app f r)
fun appi _ E = ()
  | appi f (T (l, (k, v), r)) =
    (appi f l ; f (k, v) ; appi f r)
fun map _ E = E
  | map f (T (l, (k, v), r)) = T (map f l, (k, f v), map f r)
fun mapi _ E = E
  | mapi f (T (l, (k, v), r)) = T (mapi f l, (k, f (k, v)), mapi f r)
fun mapPartial _ = die "mapPartial"
fun mapPartiali _ = die "mapPartiali"
fun foldl _ b E = b
  | foldl f b (T (l, (_, v), r)) =
    foldl f (foldl f (f (v, b)) l) r
fun foldli _ = die "foldli"
fun foldr _ = die "foldr"
fun foldri _ = die "foldri"
fun union _ = die "union"
fun unioni _ = die "unioni"
fun inter _ = die "inter"
fun interi _ = die "interi"
fun merge _ = die "merge"
fun mergi _ = die "mergi"
fun plus a b = List.foldl (fn (x, m) => update m x) a (toList b)

fun toString keyToString valueToString t =
    let
      fun toString' E = ""
        | toString' (T (l, (k, v), r)) =
          (toString' l) ^ (keyToString k) ^ ": " ^ (valueToString v) ^ "\n" ^ (toString' r)
    in
      toString' t
    end

end
