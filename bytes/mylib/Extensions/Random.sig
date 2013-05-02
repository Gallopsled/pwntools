signature Random =
sig
  include Random
structure SelfSeed : sig
  val randInt : 'a -> int
  val randNat : 'a -> int
  val randReal : 'a -> real
  val randRange : int * int -> 'a -> int
end
end
