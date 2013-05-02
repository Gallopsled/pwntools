structure IntMap = OrderedMapFn (struct
                                 type t = int
                                 fun compare x y = Int.compare (x, y)
                                 end)
