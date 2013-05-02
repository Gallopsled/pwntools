(* Default OrderedSet implementation *)

(* OrderedSetFn : Ordering -> OrderedSet *)
functor OrderedSetFn (Ord : Ordered) = RedBlackOrderedSetFn (Ord)
