

structure Quicksort :> ListSort =
struct

fun partition _ _ nil = (nil, nil)
  | partition compare pivot (x :: xs) =
    let
        val (l, g) = partition compare pivot xs
    in
        case compare x pivot of
            LESS => (x :: l, g)
          | _    => (l, x :: g)
    end

fun sort _ nil = nil
  | sort _ [x] = [x]
  | sort compare (x :: xs) =
    let
        val (l, g) = partition compare x xs
    in
        sort compare l @ x :: sort compare g
    end

end
