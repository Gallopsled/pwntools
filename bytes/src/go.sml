val version = "0.0.1"

fun usage name =
    map println
        ["usage: % [options] [file]" <- name
       , ""
       , "Options: (default marked by *)"
       , "  -r, --radix"
       , "   *a  Auto"
       , "    b  Binary"
       , "    o  Octal"
       , "    d  Decimal"
       , "    h  Hexadecimal"
       , "  -u, --unsigned"
       , "  -p, --plain"
       , "  -g, --groupsize"
       , "   *a  Auto"
       , "    n  Groups of n bytes"
       , "  -e, --endian"
       , "   *l  Little"
       , "    b  Big"
       , "  -i, --inter-byte-endian"
       , "    l  Little"
       , "   *b  Big"
       , "  -o <file>"
        ]

fun printVersionAndExit () = (println ("bytes version " ^ version)
                           ; OS.Process.exit OS.Process.success)
fun printUsageAndExit () = (usage $ CommandLine.name ()
                          ; OS.Process.exit OS.Process.success)
fun die e = (Log.warning e ; OS.Process.exit OS.Process.failure)

local
  val radix = ref NONE
  val unsigned = ref false
  val plain = ref false
  val groupsize = ref NONE
  val endian = ref Little
  val bendian = ref Big
  val src = ref NONE
  val dst = ref NONE
  fun setRadix x = radix := SOME x
  fun setUnsigned () = unsigned := true
  fun setPlain x = plain := true
  fun setGroupsize x = groupsize := SOME x
  fun setBendian x = bendian := x
  fun setEndian x = endian := x
  fun setSrc x = case !src of
                   SOME s => raise Fail ("Only one source file allowed \
                                         \(you already told me '" ^ s ^ "')")
                 | NONE => src := SOME x
  fun setDst x = dst := SOME x
  fun getOpt () =
      let
        val src = case !src of
                    SOME "-" => TextIO.stdIn
                  | SOME f   => TextIO.openIn f
                  | NONE     => printUsageAndExit ()
        val dst = case !dst of
                    SOME f => TextIO.openOut f
                  | NONE   => TextIO.stdOut
      in
        (!radix, !unsigned, !plain, !groupsize, !endian, !bendian, src, dst)
      end
      handle IO.Io {cause = OS.SysErr (desc, _), name, ...} =>
             raise Fail (desc ^ ": '" ^ name ^ "'")
in

fun parseArgs args =
    let open Parser val op >>= = op --> infix >>> ||| --|
      fun unknownOpt k v =
          raise Fail ("Unknown option (%): %" <- k <- v)
      val args =
          List.concatMap
            (fn arg =>
                case explode arg of
                  #"-" :: c :: cs =>
                  if c <> #"-" andalso not $ null cs
                  then [String.substring (arg, 0, 2)
                      , String.extract (arg, 2, NONE)]
                  else [arg]
                | _ => [arg])
            args

      val radix =
          do tok <- any
           ; return
             (case tok of
                "binary"      => setRadix Bin
              | "b"           => setRadix Bin
              | "octal"       => setRadix Oct
              | "o"           => setRadix Oct
              | "decimal"     => setRadix Dec
              | "d"           => setRadix Dec
              | "hexadecimal" => setRadix Hex
              | "h"           => setRadix Hex
              | "auto"        => ()
              | "a"           => ()
              | _             => unknownOpt "--radix" tok
             )
          end

      val groupsize =
          do tok <- any
           ; return
               (case Int.fromString tok of
                  SOME n => setGroupsize n
                | NONE   =>
                  case tok of
                    "a"    => ()
                  | "auto" => ()
                  | _      => unknownOpt "--groupsize" tok
               )
          end

      val endian =
          any >>>
              (fn "l"      => setEndian Little
                | "little" => setEndian Little
                | "b"      => setEndian Big
                | "big"    => setEndian Big
                | tok      => unknownOpt "--endian" tok
              )

      val bendian =
          any >>>
              (fn "l"      => setBendian Little
                | "little" => setBendian Little
                | "b"      => setBendian Big
                | "big"    => setBendian Big
                | tok      => unknownOpt "--inter-byte-endian" tok
              )

      fun help ? = (return $ printUsageAndExit ()) ?

      val one =
          do tok <- any
           ; case tok of
               "--radix"             => radix
             | "-r"                  => radix
             | "--unsigned"          => return $ setUnsigned ()
             | "-u"                  => return $ setUnsigned ()
             | "--plain"             => return $ setPlain ()
             | "-p"                  => return $ setPlain ()
             | "--groupsize"         => groupsize
             | "-g"                  => groupsize
             | "--endian"            => endian
             | "-e"                  => endian
             | "--inter-byte-endian" => bendian
             | "-i"                  => bendian
             | "-o"                  => any >>> setDst
             | "--help"              => help
             | "-h"                  => help
             | "-?"                  => help
             | "--version"           => return $ printVersionAndExit ()
             | _                     => return $ setSrc tok
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

fun verify (args as (radix, unsigned, plain, groupsize, endian, bendian, _, _)) =
    ((if plain andalso (radix = SOME Oct orelse radix = SOME Dec)
      then raise Fail "Only hex and binary allowed in plain mode"
      else ())
   ; Option.map (fn n => if n <= 0
                         then raise Fail "Groupsize must be strictly positive"
                         else ()) groupsize
   ; args
    )

fun go () =
    main $ verify $ parseArgs $ CommandLine.arguments ()
    handle Fail s => die s

val _ = go ()
