(* Finite map data structure with ordered keys *)

signature OrderedMap =
sig
    type key
    type 'a t

    val empty       : 'a t

    val singleton   : key * 'a -> 'a t

    (* Insert if key is not in map *)
    val insert      : 'a t -> key * 'a -> 'a t option
    val fromList    : (key * 'a) list -> 'a t

    (* Inserts or overwrites *)
    val update      : 'a t -> key * 'a -> 'a t

    (* Does nothing if the key is not in the maps domain *)
    val delete      : 'a t -> key -> 'a t

    (* May raise Domain *)
    val remove      : 'a t -> key -> 'a * 'a t
    val modify      : ('a -> 'a) -> 'a t -> key -> 'a t
    val lookup      : 'a t -> key -> 'a option

    val inDomain    : 'a t -> key -> bool
    val isEmpty     : 'a t -> bool

    val size        : 'a t -> int

    (* Ordered by keys - least to greatest *)
    val toList      : 'a t -> (key * 'a) list
    val domain      : 'a t -> key list
    val range       : 'a t -> 'a list

    (* May raise Empty *)
    val first       : 'a t -> 'a
    val firsti      : 'a t -> key * 'a
    val last        : 'a t -> 'a
    val lasti       : 'a t -> key * 'a

    val split       : 'a t -> (key * 'a) * 'a t
    val splitFirst  : 'a t -> (key * 'a) * 'a t
    val splitLast   : 'a t -> (key * 'a) * 'a t

    val collate     : ('a -> 'a -> order) -> 'a t -> 'a t -> order

    val partition   : ('a -> bool) -> 'a t -> 'a t * 'a t
    val partitioni  : (key * 'a -> bool) -> 'a t -> 'a t * 'a t
    val filter      : ('a -> bool) -> 'a t -> 'a t
    val filteri     : (key * 'a -> bool) -> 'a t -> 'a t
    val exists      : ('a -> bool) -> 'a t -> bool
    val existsi     : (key * 'a -> bool) -> 'a t -> bool
    val all         : ('a -> bool) -> 'a t -> bool
    val alli        : (key * 'a -> bool) -> 'a t -> bool
    val find        : ('a -> bool) -> 'a t -> key * 'a
    val findi       : (key * 'a -> bool) -> 'a t -> key * 'a

    (* These go from least to greatest *)
    val app         : ('a -> unit) -> 'a t -> unit
    val appi        : (key * 'a -> unit) -> 'a t -> unit
    val map         : ('a -> 'b) -> 'a t -> 'b t
    val mapi        : (key * 'a -> 'b) -> 'a t -> 'b t
    val mapPartial  : ('a -> 'b option) -> 'a t -> 'b t
    val mapPartiali : (key * 'a -> 'b option) -> 'a t -> 'b t
    val foldl       : ('a * 'b -> 'b) -> 'b -> 'a t -> 'b
    val foldli      : ((key * 'a) * 'b) -> 'b -> 'a t -> 'b

    val foldr       : ('a * 'b -> 'b) -> 'b -> 'a t -> 'b
    val foldri      : ((key * 'a) * 'b) -> 'b -> 'a t -> 'b

    val union       : ('a -> 'a -> 'a) -> 'a t -> 'a t -> 'a t
    val unioni      : (key -> 'a -> 'a -> 'a) -> 'a t -> 'a t -> 'a t
    (* return a map whose domain is the union of the domains of the two input
     * maps, using the supplied function to define the map on elements that
     * are in both domains.
     *)

    (* return a map whose domain is the intersection of the domains of the
     * two input maps, using the supplied function to define the range.
     *)
    val inter       : ('a -> 'b -> 'c) -> 'a t -> 'b t -> 'c t
    val interi      : (key -> 'a -> 'b -> 'c) -> 'a t -> 'b t -> 'c t

    (* merge two maps using the given function to control the merge. For
     * each key k in the union of the two maps domains, the function
     * is applied to the image of the key under the map.  If the function
     * returns SOME y, then (k, y) is added to the resulting map.
     *)
    val merge       : ('a option -> 'b option -> 'c option) -> 'a t -> 'b t -> 'c t
    val mergi       : (key -> 'a option -> 'b option -> 'c option) -> 'a t -> 'b t -> 'c t

    (* Return a map whose domain is the union of the domains of the two input
     * maps, always choosing the second map on elements that are in bot domains.
     *)
    val plus        : 'a t -> 'a t -> 'a t
end
