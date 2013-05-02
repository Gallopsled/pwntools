signature Debug =
sig
  (* Throw on error *)
  exception Error of string

  (* Throws Error if (lazy) condition is false *)
  val assert : string -> bool Lazy.t -> unit

  val error : string -> 'a

  (* Create a 'die' function (a function that prepends a string to its
   * argument and calls impossible *)

  val unimplemented : string -> 'a

  (* Doesn't throw Error, just prints to StdOut *)
  val debug : string -> unit
end
