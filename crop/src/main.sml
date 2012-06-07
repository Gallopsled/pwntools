fun main (window, rects, nlf, src, dst) =
    let
      (* val lines = String.fields (#"\n" \< op=) $ TextIO.inputAll src *)
      val lines =
          let
            fun loop () =
                case TextIO.inputLine src of
                  SOME line =>
                  String.substring (line, 0, size line - 1) :: loop ()
                | NONE => nil
          in
            loop ()
          end

      val numLines = length lines
      val window = getOpt (window, numLines)

      fun correct e (x, a) =
          (* x absolute, a relative *)
          if x >= 0 andalso a > 0
          then (x, x + a)
          (* x relative, a absolute *)
          else if x < 0 andalso a <= 0
          then (e + a + x, e + a)
          (* both absolute *)
          else if x >= 0 andalso a <= 0
          then (x, e + a)
          (* both relative -- an error *)
          else raise Fail ("Both indexes relative: " ^
                           Show.pair Show.int Show.int (x, a))

      val rects =
          map (Pair.mapFst $ correct window) rects

      fun line (n, l) =
          let
            val len = size l
            val (min, max) =
                foldl (fn ((b, e), (min, max)) =>
                                   (Int.min (b, min), Int.max (e, max))
                      ) (len, ~1) $
                map (fn (_, x) => correct len x) $
                List.filter (fn ((y, b), _) =>
                                let
                                  val offset = n mod window
                                in
                                  offset >= y andalso offset < b
                                end
                            ) rects
            val max = Int.min (max, len)
          in
            TextIO.output (dst, String.substring (l, min, max - min))
          ; if not nlf
            then TextIO.output (dst, "\n")
            else ()
          end
          handle Subscript => ()

    in
      app line $ ListPair.zip (List.tabulate (numLines, id), lines)
    end
