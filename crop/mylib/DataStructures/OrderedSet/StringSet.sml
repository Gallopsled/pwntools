structure StringSet = OrderedSetFn
                      (struct
                       type t = string
                       fun compare x y = String.compare (x, y)
                       end)
