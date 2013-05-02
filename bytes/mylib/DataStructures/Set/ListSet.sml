

structure ListSet :> Set =
struct

    type ''a t = ''a list

    val empty = nil

    fun singleton a = [a]

    fun member ys x = List.exists (fn y => x = y) ys

    fun insert ys x = if member ys x then ys else x :: ys

    fun delete nil _ = nil
      | delete (y :: ys) x = if y = x then ys else y :: delete ys x

    fun insertList ys xs = foldl (fn (x, ys) => insert ys x) ys xs

    fun fromList xs = insertList empty xs

    fun union xs ys = insertList xs ys

    fun inter xs ys = List.filter (fn x => member ys x) xs

    fun diff xs ys = List.filter (fn x => not (member ys x)) xs

    fun subset xs ys = List.all (fn x => member ys x) xs

    fun equal xs ys = subset xs ys andalso subset ys xs

    val isEmpty = null

    fun toList xs = xs

    val card = List.length

    fun collate cmp = raise Fail "Not implementet"

    val partition = List.partition

    val filter = List.filter

    fun remove p s = #2 (partition p s)

    val exists = List.exists

    val all = List.all

    val find = List.find

    val app = List.app

    fun map f s = foldl (fn (y, ys) => insert ys (f y)) empty s

    fun mapPartial f s =
        foldl (fn (y, ys) =>
                  case f y of
                    SOME y => insert ys y
                  | NONE   => ys
              )
              empty s

    val fold = foldl

    fun split nil = raise Empty
      | split (x::xs) = (x, xs)

    fun some (x :: _) = x
      | some _ = raise Empty

    fun toString _ nil = "{}"
      | toString pr (h :: t) =
        "{" ^
        foldl (fn (x, a) => a ^ ", " ^ pr x) (pr h) t ^
        "}"
end
