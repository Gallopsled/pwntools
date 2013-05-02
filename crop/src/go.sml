val version = "0.0.1"

fun usage name =
    map println
        ["usage: % rect [rect ...] [options]" <- name
       , ""
       , "Rect:"
       , "  <line skip>,<line count>,<char skip>,<char count>"
       , "Options:"
       , "  -w<n>, --window <n>"
       , "    Repeat for every n lines"
       , "  -n, --no-linefeed"
       , "  -o <file>"
        ]

fun printVersionAndExt () = (println ("crop version " ^ version)
                           ; OS.Process.exit OS.Process.success)
fun printUsageAndExit () = (usage $ CommandLine.name ()
                          ; OS.Process.exit OS.Process.success)
fun die e = (Log.warning e ; OS.Process.exit OS.Process.failure)

local
  val window = ref NONE
  val rects = ref nil
  val nlf = ref false
  val src = ref NONE
  val dst = ref NONE
  fun setWindow x = window := SOME x
  fun setNLF x = nlf := true
  fun addRect r = rects := r :: !rects
  fun setSrc x = case !src of
                   SOME s => raise Fail ("Only one source file allowed \
                                         \(you already told me '" ^ s ^ "')")
                 | NONE => src := SOME x
  fun setDst x = dst := SOME x
  fun getOpt () =
      let
        val src = case !src of
                    SOME f => TextIO.openIn f
                  | NONE   => TextIO.stdIn
        val dst = case !dst of
                    SOME f => TextIO.openOut f
                  | NONE   => TextIO.stdOut
      in
        (!window, !rects, !nlf, src, dst)
      end
      handle IO.Io {cause = OS.SysErr (desc, _), name, ...} =>
             raise Fail (desc ^ ": '" ^ name ^ "'")
in

fun parseArgs args =
    let open Parser val op >>= = op -->
      open (oneOf) Text
      open (comma, dash) Symb
      infix 0 |||
      infix 1 --- |-- --| ^^^ ::: @@@
      infix 2 >>> >>= ??? produce underlies

      fun unknownOpt k v =
          raise Fail ("Unknown option (%): %" <- k <- v)
      val args =
          List.concatMap
            (fn arg =>
                case explode arg of
                  #"-" :: c :: cs =>
                  if Char.isAlpha c andalso not $ null cs
                  then [String.substring (arg, 0, 2)
                      , String.extract (arg, 2, NONE)]
                  else [arg]
                | _ => [arg])
            args

      val window =
          do tok <- any
           ; return
               (case Int.fromString tok of
                  SOME n => setWindow n
                | NONE   => unknownOpt "--window" tok
               )
          end

      val num = many1 $ oneOf "0123456789-" >>> implode
      val coord = num >>> (0 \> Option.getOpt o Int.fromString)
                      ||| dash produce 0

      val rect =
          do y <- coord
           ; comma
           ; b <- coord
           ; comma
           ; x <- coord
           ; comma
           ; a <- coord
           ; return ((y, b), (x, a))
          end

      fun help ? = (return $ printUsageAndExit ()) ?

      val one =
          do tok <- any
           ; case tok of
               "--window"     => window
             | "-w"           => window
             | "-no-linefeed" => return $ setNLF ()
             | "-n"           => return $ setNLF ()
             | "-o"           => any >>> setDst
             | "--help"       => help
             | "-h"           => help
             | "-?"           => help
             | "--version"    => return $ printVersionAndExt ()
             | _              => return
               (case Parse.string rect tok of
                  Right r => addRect r
                | Left _  => setSrc tok
               )
          end
      val parse =
          do many' one
           ; eof
          end
    in
      case Parse.list parse args of
        Right _ => getOpt ()
      | Left ({token = SOME x, ...} :: _) =>
        raise Fail ("Could not parse command line arguments\
                    \ (failed on '" ^ x ^ "')")
      | Left _ =>
        raise Fail ("Could not parse command line arguments")
    end
end

fun verify (args as (window, rects, _, _, _)) =
    ((if null rects
      then raise Fail "No rects given"
      else ())
   ; Option.map (fn n => if n <= 0
                         then raise Fail "Window must be strictly positive"
                         else ()) window
   ; args
    )

fun go () =
    main $ verify $ parseArgs $ CommandLine.arguments ()
    handle Fail s => die s

val _ = go ()
