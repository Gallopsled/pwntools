structure ListTree :> Tree =
struct
fun die s = raise Fail "ListTree"

datatype 'a t = T of 'a * 'a t list

fun singleton x = T(x, nil)

fun join x ts = T(x, ts)

fun insert (T (x, ts)) y = T (x, T (y, nil) :: ts)

fun insertTree (T (x, ts)) t = T (x, t :: ts)

fun this (T (x, _)) = x

fun children (T (_, ts)) = ts

fun map f (T (x, ts)) = T (f x, List.map (map f) ts)

fun mapPartial f (T (x, ts)) =
    Option.map (fn x' => T (x', List.mapPartial (mapPartial f) ts)) (f x)

fun fold f b (T (x, ts)) = foldl (fn (t, a) => fold f a t) (f (x, b)) ts

fun mapChildren f (T (x, ts)) =
    T (x, List.map (fn T (x, ts) => T (f x, ts)) ts)

fun mapChildrenPartial f (T (x, ts)) =
    T (x, List.mapPartial
          (fn T (x, ts) =>
              case f x of
                SOME x' => SOME (T (x', ts))
              | NONE    => NONE
          )
          ts
      )

fun foldlChildren f b t = foldl (f o Arrow.first this) b (children t)
fun foldrChildren f b t = foldr (f o Arrow.first this) b (children t)

fun toList t = fold op:: nil t

fun size (T (_, ts)) = foldl (op+ o Arrow.first size) 1 ts

fun height (T (_, ts)) = foldl (Int.max o Arrow.first height) 0 ts + 1

structure Monolith =
struct
type node = int list
type 'a t = 'a t
exception Node

structure Node =
struct
type t = node
fun toString [n] = Int.toString n
  | toString (n :: ns) = Int.toString n ^ "," ^ toString ns
  | toString _ = ""
fun fromString s =
    List.map (valOf o Int.fromString)
             (String.tokens (fn c => c = #",") s)
    handle Option.Option => raise Node
end

val root = nil

(* val create = singleton *)
(* fun insertTrees (T (x, ts)) nil ts' = T (x, ts' @ ts) *)
(*   | insertTrees (T (x, ts)) (n :: ns) ts' = *)
(*     let *)
(*       fun loop (t :: ts) 0 = insertTrees t ns ts' :: ts *)
(*         | loop (t :: ts) n = t :: loop ts (n - 1) *)
(*     in *)
(*       T (x, loop ts n) *)
(*     end *)
(* fun insertTree t n t' = insertTrees t n [t'] *)
(* fun insert t n x = insertTree t n (singleton x) *)

val create = die
val insert = die
val insertTree = die
val insertTrees = die
val insertList = die

val remove = die
val delete = die
val lookup = die
val children = die
val parent = die
val sub = die
val modify = die
val update = die
end

structure Walk =
struct
type 'a tree = 'a t
type 'a t = 'a tree * 'a tree list
fun init t = (t, nil)
fun here (t, _) = t
fun this (T (x, _), _) = x
fun children (p as T (_, ts), w) =
    List.map (fn t => (t, p :: w)) ts
fun parent (_, p :: w) = SOME (p, w)
  | parent _ = NONE
end

end
