structure CharMap = OrderedMapFn
                      (struct
                       type t = char
                       fun compare x y = Char.compare (x, y)
                       end)
