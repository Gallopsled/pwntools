functor UnbalancedOrderedSetFn (Elm : Ordered) :> OrderedSet where type element = Elm.t =
struct
fun die _ = raise Fail "UnbalancedOrderedSetFn: Unimplemented"

type element = Elm.t
datatype t = E
           | T of t * element * t

val empty = E

fun singleton x = T (E, x, E)

fun insert E x = singleton x
  | insert (t as T (l, y, r)) x =
    case Elm.compare x y of
      GREATER => T (l, y, insert r x)
    | LESS    => T (insert l x, y, r)
    | EQUAL   => t

val fromList = List.foldl (fn (x, s) => insert s x) empty

fun splitLeast E = raise Empty
  | splitLeast (T (E, x, r)) = (x, r)
  | splitLeast (T (l, x, r)) =
    let
      val (y, l') = splitLeast l
    in
      (y, T (l', x, r))
    end

fun splitGreatest E = raise Empty
  | splitGreatest (T (l, x, E)) = (x, l)
  | splitGreatest (T (l, x, r)) =
    let
      val (y, r') = splitLeast r
    in
      (y, T (l, x, r'))
    end

(* Crude balancing *)
val goLeft = ref true
fun split t = if (!goLeft before goLeft := not (!goLeft)) then
                splitLeast t
              else
                splitGreatest t

fun delete E _ = E
  | delete (T (l, y, r)) x =
    case Elm.compare x y of
      GREATER => T (l, y, delete r x)
    | LESS    => T (delete l x, y, r)
    | EQUAL   =>
      let
        val (y', l') = splitGreatest l
      in
        T (l', y', r)
      end

fun toList E = nil
  | toList (T (l, x, r)) = toList l @ x :: toList r

fun union s E = s
  | union s (T (l, x, r)) = insert (union (union s l) r) x

fun member E _ = false
  | member (T (l, y, r)) x =
    case Elm.compare x y of
      GREATER => member r x
    | LESS    => member l x
    | EQUAL   => true

fun isEmpty E = true
  | isEmpty _ = false

val inter = die
val diff = die

val subset = die
val equal = die
val compare = die
val card = die
val partition = die
val filter = die
val exists = die
val all = die
val find = die
val app = die
val map = die
val mapPartial = die
val fold = die
val foldl = die
val foldr = die
val least = die
val greatest = die
val some = die
val toString = die
end
