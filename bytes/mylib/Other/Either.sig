signature Either =
sig
  datatype ('a, 'b) t = Left of 'a | Right of 'b
  exception Either

  val ofLeft : ('a, 'b) t -> 'a
  val ofRight : ('a, 'b) t -> 'b
  val either : ('a -> 'c) -> ('b -> 'c) -> ('a, 'b) t -> 'c
  val lefts : ('a, 'b) t list -> 'a list
  val rights : ('a, 'b) t list -> 'b list
  val partition : ('a, 'b) t list -> 'a list * 'b list
end
