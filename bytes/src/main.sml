(* fun impossible s = raise FailWithPosition $ "Impossible: %" <- s *)
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

      val auto = try do strings ["0x", "0X", "\\x", "\\X"]
                      ; many1 hexdig >>> (16, 1,)
                     end |||
                 try do char #"0"
                      ; many1 octdig >>> (8, 1,)
                     end |||
                 try do char #"\\"
                      ; count 3 octdig >>> (8, 1,)
                     end |||
                     do ds <- many1 hexdig
                      ; if List.exists (9 \< op<) ds
                        then return (16, 1, ds)
                        else return (10, 1, ds)
                     end

      fun signed p = do oneOf "-~"
                      ; (b, _, n) <- p
                      ; return (b, ~1, n)
                     end ||| p

      fun valuate (b, s, ds) = s * foldl (fn (d, s) => s * b + d) 0 ds

      fun read strm = Option.map (, strm) $ TextIO.input1 src
      val lst = LazyList.tabulateN
                  (fn _ => case TextIO.input1 src of
                             SOME c => c
                           | NONE   => raise LazyList.Stop
                  )

      fun write1 b =
          TextIO.output1 (dst, chr $ Int.fromLarge b)

      val goPlain =
        let
          val groupsize = getOpt (groupsize, 1)
          val radix = getOpt (radix, Hex)
          fun groups n e xs =
              (if e = Little then rev else id) (List.take (xs, n)) ::
              groups n e (List.drop (xs, n))
              handle Subscript => []
          (* a byte is `n` base `b` digits in `e` endian order *)
          fun go n b =
              app write1 o
              List.concat o
              groups groupsize endian o
              map (valuate o (b, 1,)) o
              groups n bendian o
              List.concat
        in
          case radix of
            Hex =>
            do whitespace
             ; ds <- many $ Lex.lexeme hex
             ; eof
             ; return $ go 2 16 ds
            end
          | Bin =>
            do whitespace
             ; ds <- many $ Lex.lexeme bin
             ; eof
             ; return $ go 8 2 ds
            end
          | _ => impossible "main.goPlain"
        end

      val goAuto =
          let
            val num =
                (if unsigned then id else signed)
                  (case radix of
                     NONE     => auto
                   | SOME Bin => bin >>> (2, 1,)
                   | SOME Oct => oct >>> (8, 1,)
                   | SOME Dec => dec >>> (10, 1,)
                   | SOME Hex => hex >>> (16, 1,)
                ) >>> valuate

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
                      else Int.+ (1, log (n div fromInt 256))
                in
                  log (max - min)
                end

            (* Negative numbers just work magically *)
            fun write n x =
                let
                  fun loop 0 _ = []
                    | loop n x =
                      let
                        val (b, x') = (x mod fromInt 256
                                     , x div fromInt 256)
                      in
                        b :: loop (Int.- (n, 1)) x'
                      end
                in
                  case endian of
                    Little => app write1 $ loop n x
                  | Big    => app write1 $ rev $ loop n x
                end

            fun go groupsize =
                app (write groupsize)

            (* I haven't decided if I wan't the following or not. The principle
             * of least surprise says no -- consider:
             *   good = [0x41, 0x42];
             * vs
             *   bad = [0x41, 0x42];
             *
             * The former would be 2 bytes and the latter 3. Opposed to both
             * being 3 bytes.
             *)
            val interesting = "0123456789abcdefABCDEF-~\\xX"
            val skip = many $ noneOf interesting
            fun parse ? =
                (do n <- num
                  ; notFollowedBy $ oneOf interesting
                  ; skip
                  ; ns <- parse
                  ; return (n :: ns)
                 end |||
                 do many1 $ oneOf interesting
                  ; skip
                  ; parse
                 end |||
                 do eof
                  ; return []
                 end) ?
          in
            do skip
             (* ; ns <- parse *)
             ; ns <- many $ match num
             ; groupsize := case groupsize of
                              NONE => autosize ns
                            | SOME n => n
             ; return $ go groupsize ns
            end
          end

      val go =
          if plain
          then goPlain
          else goAuto
    in
      Parse.testString go $ TextIO.inputAll src
    end
