(* Default OrderedMap implementation *)

(* OrderedMapFn : Ordering -> OrderedMap *)

functor OrderedMapFn (Key : Ordered) = UnbalancedOrderedMapFn (Key)
(* functor OrderedMapFn (Key : Ordered) = SMLNJMapFn (Key) *)
