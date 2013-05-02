signature File =
sig
  eqtype t

  (* val copy : {from : t, to : t} -> unit *)
  (* val move : {from : t, to : t} -> unit *)
  (* val create: t -> unit (\* make an empty file if file does not exists *\) *)
  (* val remove : t -> unit *)

  (* val temp : unit -> t *)

  (* val read : t -> string *)
  (* val write : t -> string -> unit *)
  val size : t -> int (* in bytes *)
  val modtime : t -> Time.time

  val openIn : t -> TextIO.instream
  val openOut : t -> TextIO.outstream
  val openAppend : t -> TextIO.outstream

  val exists : t -> bool
  val readable : t -> bool
  val writable : t -> bool

  (* val withIn : t -> (TextIO.instream -> 'a) -> 'a *)
  (* val withOut : t -> (TextIO.outstream -> 'a) -> 'a *)
  (* val withAppend : t -> (TextIO.outstream -> 'a) -> 'a *)
end where type t = Path.t
