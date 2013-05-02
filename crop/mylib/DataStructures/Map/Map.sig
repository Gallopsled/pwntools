(* Finite map data structure *)

signature Map =
sig
    type (''a, 'b) t

    val empty       : (''a, 'b) t

    val singleton   : ''a * 'b -> (''a, 'b) t

    (* Insert if key is not in t *)
    val insert      : (''a, 'b) t -> ''a * 'b -> (''a, 'b) t option
    val fromList    : (''a * 'b) list -> (''a, 'b) t

    (* Inserts if key is not in the maps domain *)
    val update      : (''a, 'b) t -> ''a * 'b -> (''a, 'b) t

    (* May raise Domain *)
    val remove      : (''a, 'b) t -> ''a -> 'b * (''a, 'b) t
    val delete      : (''a, 'b) t -> ''a -> (''a, 'b) t
    val modify      : ('b -> 'b) -> (''a, 'b) t -> ''a -> (''a, 'b) t
    val lookup      : (''a, 'b) t -> ''a -> 'b option

    val inDomain    : (''a, 'b) t -> ''a -> bool
    val isEmpty     : (''a, 'b) t -> bool

    val size        : (''a, 'b) t -> int

    val toList      : (''a, 'b) t -> (''a * 'b) list
    val domain      : (''a, 'b) t -> ''a list
    val range       : (''a, 'b) t -> 'b list
    val split       : (''a, 'b) t -> (''a * 'b) * (''a, 'b) t

    val collate     : ('b -> 'b -> order) -> (''a, 'b) t -> (''a, 'b) t -> order

    val partition   : ('b -> bool) -> (''a, 'b) t -> (''a, 'b) t * (''a, 'b) t
    val partitioni  : (''a * 'b -> bool) -> (''a, 'b) t -> (''a, 'b) t * (''a, 'b) t
    val filter      : ('b -> bool) -> (''a, 'b) t -> (''a, 'b) t
    val filteri     : (''a * 'b -> bool) -> (''a, 'b) t -> (''a, 'b) t
    val exists      : ('b -> bool) -> (''a, 'b) t -> bool
    val existsi     : (''a * 'b -> bool) -> (''a, 'b) t -> bool
    val all         : ('b -> bool) -> (''a, 'b) t -> bool
    val alli        : (''a * 'b -> bool) -> (''a, 'b) t -> bool
    val find        : ('b -> bool) -> (''a, 'b) t -> ''a * 'b
    val findi       : (''a * 'b -> bool) -> (''a, 'b) t -> ''a * 'b

    val app         : ('b -> unit) -> (''a, 'b) t -> unit
    val appi        : (''a * 'b -> unit) -> (''a, 'b) t -> unit
    val map         : ('b -> 'c) -> (''a, 'b) t -> (''a, 'c) t
    val mapi        : (''a * 'b -> 'c) -> (''a, 'b) t -> (''a, 'c) t
    val fold        : ('b * 'c -> 'c) -> 'c -> (''a, 'b) t -> 'c
    val foldi       : ((''a * 'b) * 'c -> 'c) -> 'c -> (''a, 'b) t -> 'c

    (* return a map whose domain is the union of the domains of the two input
     * maps, using the supplied function to define the map on elements that
     * are in both domains.
     *)
    val union       : ('b -> 'b -> 'b) -> (''a, 'b) t -> (''a, 'b) t -> (''a, 'b) t
    val unioni      : ('a -> 'b -> 'b -> 'b) -> (''a, 'b) t -> (''a, 'b) t -> (''a, 'b) t

    (* return a map whose domain is the intersection of the domains of the
     * two input maps, using the supplied function to define the range.
     *)
    val inter       : ('b -> 'c -> 'd) -> (''a, 'b) t -> (''a, 'c) t -> (''a, 'd) t
    val interi      : (''a -> 'b -> 'c -> 'd) -> (''a, 'b) t -> (''a, 'c) t -> (''a, 'd) t

    (* merge two maps using the given function to control the merge. For
     * each key k in the union of the two maps domains, the function
     * is applied to the image of the key under the map.  If the function
     * returns SOME y, then (k, y) is added to the resulting map.
     *)
    val merge       : ('b option -> 'c option -> 'd option) -> (''a, 'b) t -> (''a, 'c) t -> (''a, 'd) t
    val mergei      : (''a -> 'b option -> 'c option -> 'd option) -> (''a, 'b) t -> (''a, 'c) t -> (''a, 'd) t

    (* Return a map whose domain is the union of the domains of the two input
     * maps, always choosing the second map on elements that are in bot domains.
     *)
    val plus        : (''a, 'b) t -> (''a, 'b) t -> (''a, 'b) t
end
