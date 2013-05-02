signature Tree =
sig
    type 'a t
    val singleton : 'a -> 'a t
    val join : 'a -> 'a t list -> 'a t

    val insert : 'a t -> 'a -> 'a t
    val insertTree : 'a t -> 'a t -> 'a t

    val this : 'a t -> 'a
    val children : 'a t -> 'a t list

    val map : ('a -> 'b) -> 'a t -> 'b t
    (* mapPartial: If f returns NONE on a node, the node is deleted except if it
       is the root node in which case NONE is returned. *)
    val mapPartial : ('a -> 'b option) -> 'a t -> 'b t option
    (* fold: inorder *)
    val fold : ('a * 'b -> 'b) -> 'b -> 'a t -> 'b

    (*  *)
    (* val translate : ('a -> 'a list) -> 'a t -> 'a t *)

    val mapChildren : ('a -> 'a) -> 'a t -> 'a t
    val mapChildrenPartial : ('a -> 'a option) -> 'a t -> 'a t
    val foldlChildren : ('a * 'b -> 'b) -> 'b -> 'a t -> 'b
    val foldrChildren : ('a * 'b -> 'b) -> 'b -> 'a t -> 'b

    val toList : 'a t -> 'a list

    val size : 'a t -> int
    val height : 'a t -> int

    structure Monolith : sig
      eqtype node
      type 'a t
      structure Node : sig
        eqtype t
        val toString : t -> string
        val fromString : string -> t
      end where type t = node

      (* No such node in tree *)
      exception Node

      val root : node

      val create : 'a -> 'a t
      val insert : 'a t -> node -> 'a -> node * 'a t
      val insertList : 'a t -> node -> 'a list -> node list * 'a t
      val insertTree : 'a t -> node -> 'a t -> node * 'a t
      val insertTrees : 'a t -> node -> 'a t list -> node list * 'a t

      val remove : 'a t -> node -> 'a t * 'a t
      val delete : 'a t -> node -> 'a t

      val lookup : 'a t -> node -> 'a
      val children : 'a t -> node -> node list
      val parent : 'a t -> node -> node option
      val sub : 'a t -> node -> 'a t
      val modify : ('a -> 'a) -> 'a t -> node -> 'a t
      val update : 'a t -> node -> 'a -> 'a t
    end where type 'a t = 'a t

    structure Walk : sig
        type 'a tree
        type 'a t
        val init : 'a tree -> 'a t
        val here : 'a t -> 'a tree
        val this : 'a t -> 'a
        val children : 'a t -> 'a t list
        val parent : 'a t -> 'a t option
    end where type 'a tree = 'a t
end
