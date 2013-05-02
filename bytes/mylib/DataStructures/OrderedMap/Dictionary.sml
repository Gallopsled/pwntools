(* A dictionary is a mapping from strings to some domain *)

structure Dictionary = OrderedMapFn (struct
                                     type t = string
                                     fun compare x y = String.compare (x, y)
                                     end)
