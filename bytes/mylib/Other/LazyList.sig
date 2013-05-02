signature LazyList =
sig
  datatype 'a t' = Cons of 'a * 'a t' Lazy.t
                 | Nil
  type 'a t = 'a t' Lazy.t

  val eager : 'a List.list -> 'a t
  val force : 'a t -> 'a List.list
  (* Alias for getItem *)
  val split : 'a t -> ('a * 'a t) option
  val cons : 'a Lazy.t * 'a t -> 'a t

  (* val nil : 'a t
   * Because of value polymorphism nil can't be defined. Insted use
   * eager nil
   *)

  val consEager : 'a * 'a t -> 'a t
  val singleton : 'a -> 'a t

  (* These work just like for regular lists. So see
   * http://www.standardml.org/Basis/list.html
   *
   * Note: Since lazy list have the potential to be infinit these functions
   * can be hazardous: length, last, app, find, foldl, foldr, exists, all
   * (raising an exception can stop the evaluation of a (possibly infinit)
   * list).
   *
   * Note': The functions are generally as lazy as possible. Example: while
   * {take ([1], 2)} raises Subscript for regular lists {take (eager [1], 2)}
   * only raises Subscript if more than one element of the resulting lazy list
   * is ever consumed. *)
  val null : 'a t -> bool
  val length : 'a t -> int
  val @ : 'a t * 'a t -> 'a t
  val hd : 'a t -> 'a
  val tl : 'a t -> 'a t
  val last : 'a t -> 'a
  val getItem : 'a t -> ('a * 'a t) option
  val nth : 'a t * int -> 'a
  val take : 'a t * int -> 'a t
  val drop : 'a t * int -> 'a t
  val rev : 'a t -> 'a t
  val concat : 'a t t -> 'a t
  val revAppend : 'a t * 'a t -> 'a t
  val app : ('a -> unit) -> 'a t -> unit
  val map : ('a -> 'b) -> 'a t -> 'b t
  val mapPartial : ('a -> 'b option) -> 'a t -> 'b t
  val find : ('a -> bool) -> 'a t -> 'a option
  val filter : ('a -> bool) -> 'a t -> 'a t
  val partition : ('a -> bool) -> 'a t -> 'a t * 'a t
  val foldl : ('a * 'b -> 'b) -> 'b -> 'a t -> 'b
  val foldr : ('a * 'b -> 'b) -> 'b -> 'a t -> 'b
  val exists : ('a -> bool) -> 'a t -> bool
  val all : ('a -> bool) -> 'a t -> bool
  val tabulate : int * (int -> 'a) -> 'a t
  val collate : ('a * 'a -> order) -> 'a t * 'a t -> order

  (* Extra *)
  (* In increasing magnitude, positive numbers before negative. The naturals start at 0 *)
  exception Stop
  val tabulateN : (int -> 'a) -> 'a t
  (* val tabulateZ : (int -> 'a) -> 'a t *)
  (* val tabulateQ : (int * int -> 'a) -> 'a t *)
  (* val tabulatePrimes : (int -> 'a) -> 'a t *)
  (* val tabulateFibonacci : (int -> 'a) -> 'a t *)
  (* val tabulateBell : (int -> 'a) -> 'a t *)
  (* val tabulateCatalan : (int -> 'a) -> 'a t *)
  (* val tabulateFactorial : (int -> 'a) -> 'a t *)

  (* val sort : ('a -> 'a -> order) -> 'a t -> 'a t *)
  (* val shuffle : 'a t -> 'a t *)
  (* val leftmost  : 'a option t -> 'a option *)
  (* val rightmost : 'a option t -> 'a option *)
  val allPairs : 'a t -> 'b t -> ('a * 'b) t
  (* val splitAt : 'a t * int -> 'a t * 'a t *)
  (* val allSplits : 'a t -> ('a t * 'a t) t *)
  (* val consAll : 'a * 'a t t -> 'a t t *)
  (* val concatMap : ('a -> 'b t) -> 'a t -> 'b t *)
  (* val range : int -> int -> 'a t -> 'a t *)
  (* val power : 'a t -> 'a t t *)
  (* val group : ('a -> 'a -> bool) -> 'a t -> 'a t t *)

  val fromFile : string -> char t
end
