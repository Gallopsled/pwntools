signature Pair =
sig
  type ('a, 'b) t = 'a * 'b

  (* structure Iso : *)
  (*           sig *)
  (*             val toPair *)
  (*             val fromPair *)
  (*             val toTriple *)
  (*             val fromTriple *)
  (*             val toQuadruple *)
  (*             val fromQuadruple *)
  (*           end *)

  val swap : 'a * 'b -> 'b * 'a
  val swizzle : ('a * 'b) * ('c * 'd) -> ('a * 'c) * ('b * 'd)
  val fst : 'a * 'b -> 'a
  val snd : 'a * 'b -> 'b
  val app : ('a -> unit) * ('b -> unit) -> 'a * 'b -> unit
  val appFst : ('a -> unit) -> 'a * 'b -> unit
  val appSnd : ('b -> unit) -> 'a * 'b -> unit
  val map : ('a -> 'c) * ('b -> 'd) -> 'a * 'b -> 'c * 'd
  val mapFst : ('a -> 'c) -> 'a * 'b -> 'c * 'b
  val mapSnd : ('b -> 'c) -> 'a * 'b -> 'a * 'c
  val foldl : ('a * 'c -> 'c) * ('b * 'c -> 'c) -> 'c -> 'a * 'b -> 'c
  val foldr : ('a * 'c -> 'c) * ('b * 'c -> 'c) -> 'c -> 'a * 'b -> 'c
  val delay : 'a Lazy.t * 'b Lazy.t -> ('a * 'b) Lazy.t
end
