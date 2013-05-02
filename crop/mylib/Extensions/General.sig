signature General =
sig
  (* infix 5 ^* to
   * infix 4 \< \>
   * infix 3 $
   *)
  include GENERAL where type unit = unit
                    and type order = order
                    and type exn = exn
  val id : 'a -> 'a
  val ^* : ('a -> 'a) * int -> 'a -> 'a
  val $ : ('a -> 'b) * 'a -> 'b
  val flip : ('a * 'b -> 'c) -> 'b * 'a -> 'c
  val \< : 'a * ('a * 'b -> 'c) -> 'b -> 'c
  val \> : 'b * ('a * 'b -> 'c) -> 'a -> 'c

  val flipc : ('a -> 'b -> 'c) -> 'b -> 'a -> 'c
  val curry : ('a * 'b -> 'c) -> 'a -> 'b -> 'c
  val uncurry : ('a -> 'b -> 'c) -> 'a * 'b -> 'c
  val curry3 : ('a * 'b * 'c -> 'd) -> 'a -> 'b -> 'c -> 'd
  val uncurry3 : ('a -> 'b -> 'c -> 'd) -> 'a * 'b * 'c -> 'd
  val curry4 : ('a * 'b * 'c * 'd -> 'e) ->
               'a -> 'b -> 'c -> 'd -> 'e
  val uncurry4 : ('a -> 'b -> 'c -> 'd -> 'e) ->
                 'a * 'b * 'c * 'd -> 'e
  val pair : 'a -> 'b -> 'a * 'b
  val triple : 'a -> 'b -> 'c -> 'a * 'b * 'c
  val quadruple : 'a -> 'b -> 'c -> 'd -> 'a * 'b * 'c * 'd
  val to : int * int -> int list
  val inc : int ref -> int
  val dec : int ref -> int
  val const : 'a -> 'b -> 'a
end
