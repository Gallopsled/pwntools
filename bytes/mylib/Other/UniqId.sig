signature UniqId =
sig
  (* {gen A n} generates an ID of length n from alphabet A *)
  val gen : string -> int -> string
  val next : unit -> string
end
