structure TextIO :> TextIO =
struct
open TextIO

fun println s = (print s ; print "\n")

fun readFile f =
    let
      val is = openIn f
    in
      inputAll is before closeIn is
    end

fun writeFile f s =
    let
      val os = openOut f
    in
      output (os, s) before closeOut os
    end

fun appendFile f s =
    let
      val os = openAppend f
    in
      output (os, s) before closeOut os
    end
end
