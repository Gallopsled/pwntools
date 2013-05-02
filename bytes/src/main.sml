fun impossible s = raise Fail $ "Impossible: %" <- s

datatype radix
  = Bin
  | Oct
  | Dec
  | Hex

datatype format
  = Plain

datatype endian
  = Little
  | Big

fun main (radix, unsigned, plain, groupsize, endian, bendian, src, dst) =
    let open Parser val op >>= = op -->
      open (oneOf, noneOf, char, string, strings, whitespace, alphaNum) Text
      infix 0 |||
      infix 1 --- |-- --| ^^^ ::: @@@
      infix 2 >>> >>= ??? produce underlies
      open IntInf

      fun offset n c = fromInt $ Int.- (ord c, n)

      val bindig =
          oneOf "01" >>> offset 0x30

      val octdig =
          oneOf "01234567" >>> offset 0x30

      val decdig =
          oneOf "0123456789" >>> offset 0x30

      val hexdig =
          oneOf "0123456789" >>> offset 0x30
      ||| oneOf "abcdef" >>> offset 0x57
      ||| oneOf "ABCDEF" >>> offset 0x37

      val bin = many1 bindig
      val oct = many1 octdig
      val dec = many1 decdig
      val hex = many1 hexdig

      fun signed p = do oneOf "-~"
                      ; (b, _, n) <- p
                      ; return (b, ~1, n)
                     end ||| p

      fun valuate (b, s, ns) = s * foldl (fn (d, s) => s * b + d) 0 ns

      fun read strm = Option.map (, strm) $ TextIO.input1 src

      fun write1 b =
          TextIO.output1 (dst, chr $ Int.fromLarge b)

      fun groups n e xs =
          (if e = Little then rev else id) (List.take (xs, n)) ::
          groups n e (List.drop (xs, n))
          handle Subscript => []

      fun goPlain () =
        let
          val groupsize = getOpt (groupsize, 1)
          (* val radix = getOpt (radix, Hex) *)
          (* a byte is `n` base `b` digits in `e` endian order *)
          fun go n b =
              app write1 o
              List.concat o
              groups groupsize endian o
              map (valuate o (b, 1, )) o
              groups n bendian o
              List.concat
        in
          case radix of
            SOME Hex =>
            do whitespace
             ; ds <- many $ Lex.lexeme hex
             ; eof
             ; return $ go 2 16 ds
            end
          | SOME Bin =>
            do whitespace
             ; ds <- many $ Lex.lexeme bin
             ; eof
             ; return $ go 8 2 ds
            end
          | NONE =>
            do whitespace
             ; ds <- many $ Lex.lexeme hex
             ; eof
             ; if length ds <> 1 then
                   fail
               else
                   return (
                   if List.all (fn d => d = 0 orelse d = 1) $ hd ds
                   then go 8 2 ds
                   else go 2 16 ds
                   )
            end
          | _ => fail
        end

      fun goAuto () =
          let
            val auto = try do strings ["0x", "0X", "\\x", "\\X"]
                            ; hex >>> (SOME 16, 1,)
                           end |||
                       try do d <- decdig
                            ; ds <- hex
                            ; char #"h"
                            ; return (SOME 16, 1, ds)
                           end |||
                       try do ds <- oct
                            ; char #"o"
                            ; return (SOME 8, 1, ds)
                           end |||
                       (* try do char #"0" *)
                       (*      ; oct >>> (SOME 8, 1,) *)
                       (*     end ||| *)
                       try do char #"\\"
                            ; count 3 octdig >>> (SOME 8, 1,)
                           end |||
                       hex >>> (NONE, 1,)

            val num =
                (if unsigned then id else signed)
                  (case radix of
                     NONE     => auto
                   | SOME Bin => bin >>> (SOME 2, 1,)
                   | SOME Oct => oct >>> (SOME 8, 1,)
                   | SOME Dec => dec >>> (SOME 10, 1,)
                   | SOME Hex => hex >>> (SOME 16, 1,)
                  )

            fun autosize ns =
                let
                  val (min, max) = foldl (fn (x, (min, max)) =>
                                             if x < min then (x, max)
                                             else if x > max then (min, x)
                                             else (min, max)) (0, 0) ns
                  fun isZero n = sign n = 0
                  fun log n =
                      if isZero n
                      then 0
                      else Int.+ (1, log (n div 256))
                in
                  Int.max(1, if min < 0
                             then log (max - min)
                             else log max)
                end

            fun autobase ns =
                case List.partition (fn (mbb, _, _) => mbb <> NONE) ns of
                  (nil, ns) =>
                  let
                    val max = foldl IntInf.max 0
                    val b = max $ map (fn (_, _, ds) => max ds) ns
                    val b = case (b >= 10, b >= 2) of
                              (true, _) => 16
                            | (_, true) => 10
                            | _         =>  2
                  in
                    map (fn (_, s, ns) => (b, s, ns)) ns
                  end
                | (ns, _) => map (fn (mbb, s, ns) => (valOf mbb, s, ns)) ns

            val isbits = List.all (fn (b, s, ns) => b = 2 andalso
                                                    s = 1 andalso
                                                    length ns = 1)

            (* Negative numbers just work magically *)
            fun write n x =
                let
                  fun loop 0 _ = []
                    | loop n x =
                      let
                        val (b, x') = (x mod 256
                                     , x div 256)
                      in
                        b :: loop (Int.- (n, 1)) x'
                      end
                in
                  case endian of
                    Little => app write1 $ loop n x
                  | Big    => app write1 $ rev $ loop n x
                end

            fun binary ns =
                let
                  val groupsize = case groupsize of
                                    NONE   => 1
                                  | SOME n => n
                  val bits = map (fn (_, _, ds) => hd ds) ns
                  val bytes = map (valuate o (2, 1,)) $ groups 8 bendian bits
                  val words = List.concat $ groups groupsize endian bytes
                in
                  app write1 words
                end

            fun regular ns =
                let
                  val vs = map valuate ns
                  val groupsize = case groupsize of
                                    NONE   => autosize vs
                                  | SOME n => n
                in
                  app (write groupsize) vs
                end
          in
            do ns <- many $ match num
             ; ns := autobase ns
             ; return (if isbits ns
                       then binary ns
                       else regular ns)
            end
          end

      val go =
          if plain
          then goPlain ()
          else try (goPlain ()) ||| goAuto ()
    in
      Parse.testString go $ TextIO.inputAll src
      (* test (fn c => "'" ^ str c ^ "'") *)
      (*      go *)
      (*      (Option.map (, src) o TextIO.input1) *)
      (*      src *)
    end
