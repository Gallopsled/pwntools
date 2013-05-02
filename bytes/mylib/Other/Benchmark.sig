signature Benchmark =
sig
    val start : unit -> unit
    val pause : unit -> unit
    val stop : unit -> unit
    val time : unit -> {usr : Time.time, sys : Time.time, tot : Time.time}

    (* Equivalent to stop() ; start () *)
    val restart : unit -> unit

    val show : unit -> string

    val print : string -> unit
    val stopAndPrint : string -> unit
end
