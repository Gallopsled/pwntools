signature Log =
sig
  datatype level = Debug
                 | Verbose
                 | Chatty
                 | Normal
                 | Quiet
  val setLevel : level -> unit
  val setIndentation : int -> unit
  val indent : int -> unit
  val debug : string -> unit
  val verbose : string -> unit
  val chatty : string -> unit
  val normal : string -> unit
  val warning : string -> unit
end
