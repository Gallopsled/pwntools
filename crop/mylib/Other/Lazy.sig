(* Memoized lazy evaluation *)

signature Lazy =
sig
  type 'a t
  type 'a thunk = unit -> 'a

  val lazy : 'a thunk -> 'a t
  val force : 'a t -> 'a
  val eager : 'a -> 'a t
  val delay : 'a t thunk -> 'a t
end
