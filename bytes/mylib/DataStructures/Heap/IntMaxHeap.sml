
structure IntMaxHeap = HeapFn (struct
                               type t = int
                               fun compare x y = Int.compare (y, x)
                               val toString = Int.toString
                               end)
