structure Debug : Debug =
struct
exception Error of string

fun assert msg cond =
    if Lazy.force cond then
      ()
    else
      raise Error msg

fun error msg =
    raise Error msg

fun unimplemented msg =
    raise Error ("Unimplemented: " ^ msg)

fun debug msg =
    TextIO.println ("-- " ^ msg)
end
