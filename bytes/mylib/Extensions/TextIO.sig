signature TextIO =
sig
  include TEXT_IO
  where type instream = TextIO.instream
  and type outstream  = TextIO.outstream

  val println : string -> unit
  val readFile : string -> string
  val writeFile : string -> string -> unit
  val appendFile : string -> string -> unit
end
