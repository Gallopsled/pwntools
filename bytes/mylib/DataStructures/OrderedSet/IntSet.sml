structure IntSet = OrderedSetFn
                     (struct
                      type t = int
                      fun compare x y = Int.compare (x, y)
                      end)
