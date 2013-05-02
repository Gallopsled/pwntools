(* TODO: Uncurry compare functions everywhere. That makes it easier to use built
 * in and anonymous compare functions *)
signature Ordered =
sig
    type t
    val compare  : t -> t -> order
end
