(* Finite set data structure *)

signature Set =
sig
    type ''a t

    val empty      : ''a t
    val singleton  : ''a -> ''a t
    val insert     : ''a t -> ''a -> ''a t
    val delete     : ''a t -> ''a -> ''a t
    val fromList   : ''a list -> ''a t

    val union      : ''a t -> ''a t -> ''a t
    (* val concat     : ''a t list -> ''a t *)
    val inter      : ''a t -> ''a t -> ''a t
    val diff       : ''a t -> ''a t -> ''a t

    (* subset s s': all elements in s' is also in s *)
    val subset     : ''a t -> ''a t -> bool
    val equal      : ''a t -> ''a t -> bool
    val member     : ''a t -> ''a -> bool
    val isEmpty    : ''a t -> bool

    val toList     : ''a t -> ''a list

    val card       : ''a t -> int

    val collate    : (''a -> ''a -> order) -> ''a t -> ''a t -> order
    (* val power      : ''a t -> ''a t t *)

    val partition  : (''a -> bool) -> ''a t -> ''a t * ''a t
    val filter     : (''a -> bool) -> ''a t -> ''a t
    val exists     : (''a -> bool) -> ''a t -> bool
    val all        : (''a -> bool) -> ''a t -> bool
    val find       : (''a -> bool) -> ''a t -> ''a option

    val app        : (''a -> unit) -> ''a t -> unit
    val map        : (''a -> ''b) -> ''a t -> ''b t
    val mapPartial : (''a -> ''b option) -> ''a t -> ''b t
    val fold       : (''a * 'b -> 'b) -> 'b -> ''a t -> 'b

    val split      : ''a t -> ''a * ''a t

    (* May raise Empty *)
    val some       : ''a t -> ''a
end
