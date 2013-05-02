functor TrieOrderedSetFn (Map : OrderedMap) :>
        sig
          include OrderedSet
          val prefixesOf : t -> element -> t
          val withPrefix : t -> element -> t
        end
          where type element = Map.key list =
struct
fun die _ = raise Fail "TrieTreeFn: Unimplemented"

type element = Map.key list
datatype t = T of bool * t Map.t

val empty = T (false, Map.empty)

fun insert (T (_, m)) nil = T (true, m)
  | insert (T (b, m)) (k :: ks) =
    T (b, Map.update m (k, insert (
                           case Map.lookup m k of
                             SOME t => t
                           | NONE   => empty) ks
                       )
      )

val fromList = List.foldl (fn (x, s) => insert s x) empty

fun toList (T (b, m)) =
    let
      val es = List.concat (
               List.map (fn (k, t) =>
                            List.map (fn e => k :: e) (toList t)
                        ) (Map.toList m)
               )
    in
      if b then
        nil :: es
      else
        es
    end

fun member (T (b, _)) nil = b
  | member (T (_, m)) (k :: ks) =
    case Map.lookup m k of
      SOME t => member t ks
    | NONE   => false

fun delete t k =
    let
      fun prune (T (b, m)) =
          let
            val m' = Map.mapPartial prune m
          in
            if Map.isEmpty m' andalso not b then
              NONE
            else
              SOME (T (b, m'))
          end

      fun loop nil (T (_, m)) = T (false, m)
        | loop (k :: ks) (T (b, m)) =
          T (b, Map.modify (loop ks) m k)
          handle Domain => T (b, m)
    in
      case prune (loop k t) of
        SOME t => t
      | NONE   => empty
    end

fun isEmpty (T (false, m)) = Map.isEmpty m
  | isEmpty _ = false


fun prefixesOf t p =
    let
      fun loop p (k :: ks) (T (b, m)) =
          let
            val t = case Map.lookup m k of
                      SOME t => loop (k :: p) ks t
                    | NONE   => empty
          in
            if b then
              insert t (rev p)
            else
              t
          end
        | loop _ _ _ = empty
    in
      loop nil p t
    end

fun withPrefix t p =
    let
      fun loop (T (_, m)) (k :: ks) =
          (case Map.lookup m k of
             SOME t => T (false, Map.singleton (k, withPrefix t ks))
           | NONE   => raise Empty)
        | loop (T (_, m)) nil =
          if Map.isEmpty m then
            raise Empty
          else
            T (false, m)
    in
      loop t p handle Empty => empty
    end

fun card (T (b, m)) =
    Map.foldl
      (fn (t, a) => card t + a)
      (if b then 1 else 0)
      m

val singleton = die
val delete = die
val union = die
val inter = die
val diff = die
val subset = die
val equal = die
val isEmpty = die
val compare = die
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
val split = die
val splitLeast = die
val splitGreatest = die
val least = die
val greatest = die
val some = die
val toString = die
end
