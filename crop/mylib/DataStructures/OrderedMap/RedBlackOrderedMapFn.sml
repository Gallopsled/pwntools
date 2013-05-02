functor RedBlackOrderedMapFn (Key : Ordered) :>
        OrderedMap where type key = Key.t =
struct
fun die _ = raise Fail "RedBlackOrderedMapFn: Unimplemented"

type key = Key.t

datatype color = R | B
datatype 'a t = E
              | T of color * 'a t * (key * 'a) * 'a t

val empty = E

fun singleton x = T (B, E, x, E)

local
  fun sub1 (T (B, l, y, r)) = T (R, l, y, r)
    | sub1 _ = die "Invariance violation"

  fun balance x =
      case x of
        (T (R, ll, lx, lr), x, T (R, rl, rx, rr)) =>
        T (R, T (B, ll, lx, lr), x, T (B, rl, rx, rr))
      | (T (R, T (R, lll, llx, llr), lx, lr), x, r) =>
        T (R, T (B, lll, llx, llr), lx, T (B, lr, x, r))
      | (T (R, ll, lx, T (R, lrl, lrx, lrr)), x, r) =>
        T (R, T (B, ll, lx, lrl), lrx, T (B, lrr, x, r))
      | (l, x, T (R, rl, rx, T (R, rrl, rrx, rrr))) =>
        T (R, T (B, l, x, rl), rx, T (B, rrl, rrx, rrr))
      | (l, x, T (R, T (R, rll, rlx, rlr), rx, rr)) =>
        T (R, T (B, l, x, rll), rlx, T (B, rlr, rx, rr))
      | (l, x, r) =>
        T (B, l, x, r)

  fun balanceLeft x =
      case x of
        (T (R, ll, lx, lr), x, r) =>
        T (R, T (B, ll, lx, lr), x, r)
      | (l, x, r as T (B, _, _, _)) =>
        balance (l, x, r)
      | (l, x, T (R, T (B, rll, rlx, rlr), rx, T (B, rrl, rrx, rrr))) =>
        T (R, T (B, l, x, rll), rlx, balance (rlr, rx, T (R, rrl, rrx, rrr)))
      | _ => raise Fail "RedBlackOrderedMapFn.balanceLeft: Invariance violation"

  fun balanceRight x =
      case x of
        (l, x, T (R, rl, rx, rr)) =>
        T (R, l, x, T (B, rl, rx, rr))
      | (l as T (B, _, _, _), x, r) =>
        balance (l, x, r)
      | (T (R, T (B, lll, llx, llr), lx, T (B, lrl, lrx, lrr)), x, r) =>
        T (R, balance (T (R, lll, llx, llr), lx, lrl), lrx, T (B, lrr, x, r))
      | _ => raise Fail "RedBlackOrderedMapFn.balanceRight: Invariance violation"

  fun app x =
      case x of
        (E, r) => r
      | (l, E) => l
      | (T (R, ll, lx, lr), T (R, rl, rx, rr)) =>
        (case app (lr, rl) of
           T (R, l, x, r) => T (R, T (R, ll, lx, l), x, T (R, r, rx, rr))
         | x => T (R, ll, lx, T (R, x, rx, rr))
        )
      | (T (R, ll, lx, lr), T (B, rl, rx, rr)) =>
        (case app (lr, rl) of
           T (R, l, x, r) => T (R, T (B, ll, lx, l), x, T (B, r, rx, rr))
         | x => balanceLeft (ll, lx, T (B, x, rx, rr))
        )
      | (l, T (R, rl, rx, rr)) => T (R, app (l, rl), rx, rr)
      | (T (R, ll, lx, lr), r) => T (R, ll, lx, app (lr, r))
in
fun update m (k, v) =
    let
      fun loop E = T (R, E, (k, v), E)
        | loop (T (B, l, (k', v'), r)) =
          (case Element.compare k k' of
             LESS    => balance (loop l, (k', v'), r)
           | GREATER => balance (l, (k', v'), loop r)
           | EQUAL   => T (B, l, (k, v), r)
          )
        | loop (T (R, l, (k', v'), r)) =
          (case Element.compare k k' of
             LESS    => T (R, loop l, (k', v'), r)
           | GREATER => T (R, l, (k', v'), loop r)
           | EQUAL   => T (R, l, (k, v), r)
          )
    in
      case loop m of
        T (_, l, x, r) => T (B, l, x, r)
      | _ => raise Fail "RedBlackOrderedMapFn.insert: Impossible"
    end

fun delete 
end

(* Insert if key is not in map *)
val fromList = die

(* Inserts or overwrites *)
val update = die

(* Does nothing if the key is not in the maps domain *)
val delete = die

(* May raise Domain *)
val remove = die
val modify = die
val lookup = die

val inDomain = die
val isEmpty = die

val size = die

(* Ordered by keys - least to greatest *)
val toList = die
val domain = die
val range = die

(* May raise Empty *)
val first = die
val firsti = die
val last = die
val lasti = die

val split = die
val splitFirst = die
val splitLast = die

val collate = die

val partition = die
val partitioni = die
val filter = die
val filteri = die
val exists = die
val existsi = die
val all = die
val alli = die
val find = die
val findi = die

val app = die
val appi = die
val map = die
val mapi = die
val mapPartial = die
val mapPartiali = die
val foldl = die
val foldli = die
val foldr = die
val foldri = die

val union = die
val unioni = die
(* return a map whose domain is the union of the domains of the two input
 * maps, using the supplied function to define the map on elements that
 * are in both domains.
 *)

(* return a map whose domain is the intersection of the domains of the
 * two input maps, using the supplied function to define the range.
 *)
val inter = die
val interi = die

(* merge two maps using the given function to control the merge. For
 * each key k in the union of the two maps domains, the function
 * is applied to the image of the key under the map.  If the function
 * returns SOME y, then (k, y) is added to the resulting map.
 *)
val merge = die
val mergi = die

(* Return a map whose domain is the union of the domains of the two input
 * maps, always choosing the second map on elements that are in bot domains.
 *)
val plus = die
end
