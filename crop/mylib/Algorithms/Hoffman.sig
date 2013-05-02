signature Hoffman =
sig
  type bit = bool
  type 'a codebook
  structure Codebook : sig
    val gen : int -> 'a vector -> 'a codebook
    (* val optimal : 'a vector -> 'a codebook *)
    val create : (int * 'a vector) list -> 'a codebook
    val serialize : ('a -> string) -> 'a codebook -> string
    val unserialize :  (string -> 'a) -> string -> 'a codebook
  end

  val encode : 'a codebook -> 'a vector -> bit list
  val decode : 'a codebook -> bit list -> 'a vector

  val serialize : bit list -> string
  val unserialize : string -> bit list

  val pack : ('a -> string) -> 'a codebook -> 'a vector -> string
  (* val packOptimal : ('a -> string) -> 'a vector -> string *)
  val unpack : (string -> 'a) -> string -> 'a
end
