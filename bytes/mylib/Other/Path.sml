(* TODO: Review with regard to symbolic links. As it is now, it almost certainly
   doesn't work.
   Read path variables from a file
*)

structure Path :> Path =
struct
structure P = OS.Path

(* Invariant: Values of type t represent absolute canonical paths *)
type t = string

structure Map = Dictionary
structure Set = StringSet

exception Path of string

fun path f = f
val toString = path

fun new f =
    if P.isAbsolute f then
      P.mkCanonical f
    else
      raise Path "Cannot create a relative path"

fun new' f f' =
    if P.isAbsolute f' then
      new f'
    else
      new (P.concat (f, f'))

fun append f f' = new $ toString f ^ f'

fun path' f f' = P.mkCanonical (P.mkRelative {path = f', relativeTo = f})

val file = P.file
val dir = P.dir
val base = P.base
val extension = P.ext

val sub = String.isPrefix

val show = Layout.txt
fun relative s = new' (OS.FileSys.getDir ()) s
end
