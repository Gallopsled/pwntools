

functor ListOrderedMapFn (Key : Ordered) :> OrderedMap where type key = Key.t =
struct

    type key = Key.t
    type 'a t = (key * 'a) list

    val compare = Key.compare

    val empty = nil

    fun singleton x = [x]

    fun insert nil x = SOME [x]
      | insert ((k', v') :: ys) (k, v) =
        case compare k k' of
            GREATER =>
            (case insert ys (k, v) of
                 SOME ys => SOME ((k', v') :: ys)
               | NONE    => NONE
            )
          | EQUAL   => NONE
          | LESS    => SOME ((k, v) :: (k', v') :: ys)

    fun remove nil _ = raise Domain
      | remove ((k', v') :: ys) k =
        case compare k k' of
            GREATER =>
            let
                val (v, ys') = remove ys k
            in
                (v, (k', v') :: ys')
            end
          | EQUAL   => (v', ys)
          | LESS    => raise Domain

    fun delete nil _ = nil
      | delete ((k', v') :: ys) k =
        case compare k k' of
            GREATER => (k', v') :: delete ys k
          | _       => ys

    fun update nil x = [x]
      | update ((k', v') :: ys) (k, v) =
        case compare k k' of
            GREATER => (k', v') :: update ys (k, v)
          | EQUAL   => (k, v) :: ys
          | LESS    => (k, v) :: (k', v') :: ys

    fun fromList xs = foldl (fn (x, m) => update m x) empty xs

    fun modify _ nil _ = raise Domain
      | modify f ((k', v') :: ys) k =
        case compare k k' of
            GREATER => (k', v') :: modify f ys k
          | EQUAL   => (k', f v') :: ys
          | LESS    => raise Domain

    fun lookup nil _ = NONE
      | lookup ((k', v') :: ys) k =
        case compare k k' of
            GREATER => lookup ys k
          | EQUAL   => SOME v'
          | LESS    => NONE

    fun inDomain nil _ = false
      | inDomain ((k', _) :: ys) k =
        case compare k k' of
            GREATER => inDomain ys k
          | EQUAL   => true
          | LESS    => false

    val isEmpty = null

    val size = List.length

    fun toList ys = ys

    fun domain ys = map (fn (k, _) => k) ys

    fun range ys = map (fn (_, v) => v) ys

    fun first nil = raise Empty
      | first ((_, v) :: _) = v

    fun firsti nil = raise Empty
      | firsti (y :: _) = y

    fun last nil = raise Empty
      | last ys = ((fn (_, v) => v) o hd o rev) ys

    fun lasti nil = raise Empty
      | lasti ys = hd (rev ys)

    fun splitFirst nil = raise Empty
      | splitFirst (y :: ys) = (y, ys)

    fun splitLast xs = splitFirst (rev xs)

    val split = splitFirst

    fun unimp _ = raise Fail "Not implemented"

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
    val mapPartial = unimp
    val mapPartiali = unimp
    val foldl = unimp
    val foldli = unimp
    val foldr = unimp
    val foldri = unimp

    val union = unimp
    val unioni = unimp
    val inter = unimp
    val interi = unimp

    val merge = unimp
    val mergi = unimp

    val plus = unimp

    val toString = unimp
end
