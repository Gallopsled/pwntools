signature String =
sig
  include STRING
  where type string = string
    and type char = Char.char

val TAB_WIDTH : int ref

val tabulate : int * (int -> char) -> string

val intercalate : string -> string list -> string

(* Max width -> text -> wordwrapped text *)
val wordwrap : int -> string -> string

(* Tab width -> text with tabs -> text without tabs *)
val untabify : int -> string -> string

val spaces : int -> string

val <- : string * string -> string
end
