structure CList :> CList =
struct
datatype 'a clist = L of 'a list
                  | C of 'a clist * 'a clist

val empty = L nil
fun singleton x = L [x]
fun @@ (L nil, ys) = ys
  | @@ (xs, L nil) = xs
  | @@ ls = C ls

fun toList xs =
    let
      fun loop (L xs, zs) = xs @ zs
        | loop (C (xs, ys), zs) = loop (xs, loop (ys, zs))
    in
      loop (xs, nil)
    end

fun fromList xs = L xs

fun length xs =
    let
      fun loop (L xs, n) = List.length xs + n
        | loop (C (xs, ys), n) = loop (xs, loop (ys, n))
    in
      loop (xs, 0)
    end
end
