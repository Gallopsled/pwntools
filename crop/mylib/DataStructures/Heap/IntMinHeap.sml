
structure IntMinHeap = HeapFn (struct
                               type t = int
                               fun compare x y = Int.compare (x, y)
                               val toString = Int.toString
                               end)
