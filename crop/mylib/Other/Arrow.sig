signature Arrow =
sig
  (* infix 4 ** && ++ || \< \>
   * infix 3 << >>
   *)
  type ('a, 'b) t = 'a -> 'b

  val id : ('a, 'a) t
  val const : 'a -> ('b, 'a) t
  val flip : ('a * 'b, 'c) t -> ('b * 'a, 'c) t

  val first : ('a, 'b) t -> ('a * 'c, 'b * 'c) t
  val second : ('a, 'b) t -> ('c * 'a, 'c * 'b) t

  val ** : ('a, 'b) t * ('c, 'd) t -> ('a * 'c, 'b * 'd) t
  val && : ('a, 'b) t * ('a, 'c) t -> ('a, 'b * 'c) t

  val left : ('a, 'b) t -> (('a, 'c) Either.t, ('b, 'c) Either.t) t
  val right : ('a, 'b) t -> (('c, 'a) Either.t, ('c, 'b) Either.t) t

  val ++ : ('a, 'b) t * ('c, 'd) t -> (('a, 'c) Either.t, ('b, 'd) Either.t) t
  val || : ('a, 'c) t * ('b, 'c) t -> (('a, 'b) Either.t, 'c) t

  val >> : ('a, 'b) t * ('b, 'c) t -> ('a, 'c) t
  val << : ('b, 'c) t * ('a, 'b) t -> ('a, 'c) t

  val \< : 'a * ('a * 'b, 'c) t -> ('b, 'c) t
  val \> : 'b * ('a * 'b, 'c) t -> ('a, 'c) t
end
