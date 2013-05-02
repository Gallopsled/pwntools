signature Path =
sig
  eqtype t

  exception Path of string

  (* relative to current directory *)
  val relative : string -> t

  (* Raises Path if the argument is a relative path. *)
  val new : string -> t

  (* Relative to first argument.
     Ignores first argument if second argument is an absolute path. *)
  val new' : t -> string -> t
  (* alias *)
  val append : t -> string -> t

  val path : t -> string
  (* Alias *)
  val toString : t -> string
  (* Relative to first argument *)
  val path' : t -> t -> string

  val file : t -> string
  val dir : t -> t
  val base : t -> string
  val extension : t -> string option

  (* Second argument is a subpath of first argument. *)
  (* maybe rename to isPrefix *)
  val sub : t -> t -> bool

  val show : t -> Layout.t

  structure Set : OrderedSet where type element = t
  structure Map : OrderedMap where type key = t
end
