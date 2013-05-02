(* The way it works, is that Layout is an extension of Pretty. So every
 * declaration in Pretty is also in Layout. Think of it as Pretty defining the
 * basic operations and Layout building sugar on top of that.
 *)

(* TODO
 * Make a suite of examples.
 *)

signature Layout =
sig
  (* infix ^^ ++ \ & \\ && *)
  include Pretty

  (* Prints to standard out (with an extra \n). Takes an optional max width. *)
  val println : int option -> t -> unit

  (* A space if the output fits, new line and indent if it doesn't. *)
  val softln : t

  (* Nothing if the output fits, new line and indent if it doesn't. *)
  val softbrk : t

  (* Replaces all spaces with softln. *)
  val softtxt : string -> t

  (* Like softtxt but preprends two spaces. *)
  val paragraph : string -> t

  (* Converts a preformatted text into a document. A newline character separates
   * paragraphs and the following number of spaces determine the next paragraphs
   * indentation. So it basically does what you would expect. *)
  val str : string -> t

  (* Takes the desired bullet as a string *)
  val itemize : string -> t list -> t

  datatype enumeration = Number | Letter | Roman | CapitalLetter | CapitalRoman
  (* Takes an enumeration schema (which is a string to print before each
   * enumeration, a kind of enumeration, and a string to print after) and an
   * optional starting number (default is 1). *)
  val enumerate : string * enumeration * string -> int option -> t list -> t

  (* Double spaces after the word being described, following lines indented. *)
  val description : (string * t) list -> t

  (* Places one document besides another. The first argument determines the
   * spacing *)
  val besides : int -> t * t -> t

  (* Flushes to the right if a maximum width is given. Does nothing otherwise *)
  val flushRight : t -> t

  (* Indents a document. The indented document should follow a line break. *)
  val indent : int -> t -> t

  (* As align except the lines following the first one is indented further. *)
  val hang : int -> t -> t

  (* Aligns the lines of a document vertically (modulo internal indentation). *)
  val align : t -> t

  (* Takes a function that given the printed width of a document generates a
   * second document. The two documents are then joined. *)
  val width : (int -> t) -> t -> t

  (* Takes function that given the columns left until the desired maximum width
   * is reached produces a document *)
  val left : (int option -> t) -> t

  (* Takes a function that given the number of lines printed so far produces a
   * document.
   *)
  val row : (int -> t) -> t

  (* Takes a function that given the current column produces a document.
   *)
  val column : (int -> t) -> t

  (* Place a document at a specific position if that position is not already
   * reached (in wich case the document is printed immediately.
   * Rows and columns are zero indexed.
   *)
  val placeAt : {row: int, column: int} -> t -> t

  (* Takes a desired width and a document. Appends spaces if the document is
   * narrower, or inserts a line break and indents if it isn't. *)
  val fillBreak : int -> t -> t

  (* Takes a desired width and appends spaces to a document if it is narrower or
   * does nothing if it isn't. *)
  val fill : int -> t -> t

  val ++ : t * t -> t (* l ++ r = l ^^ txt " " ^^ r *)
  val \  : t * t -> t (* l \\ r = l ^^ ln ^^ r      *)
  val &  : t * t -> t (* l \ r  = l ^^ softln ^^ r  *)
  val \\ : t * t -> t (* l \\ r = l ^^ brk ^^ r     *)
  val && : t * t -> t (* l && r = l ^^ softbrk ^^ r *)

  (* Lays out its elements horizontally *or* vertically; nothing in between. *)
  val sep : t list -> t (* sep = group o vsep *)
  val cat : t list -> t (* cat = group o vcat *)

  (* Concatenates a document to the right of each document in the list, except
   * the last one. *)
  val punctuate : t -> t list -> t list

  (* Seperate (As concatenate but always puts something between the documents,
   * eg. a space or a new line). *)
  val hsep : t list -> t (* With txt " " *)
  val vsep : t list -> t (* With nl      *)
  (* Lays out as much as it can before a line break *)
  val fsep : t list -> t (* With softnl  *)

  (* Concatenate. *)
  val hcat : t list -> t (* With empty   *)
  val vcat : t list -> t (* With brk     *)
  (* Lays out as much as it can before a line break *)
  val fcat : t list -> t (* With softbrk *)


  val enclose : t * t -> t -> t (* enclose (l, r) d = l ^^ d ^^ r *)
  val plings : t -> t           (* = enclose (pling, pling)       *)
  val quotes : t -> t           (* = enclose (quote, quote)       *)
  val parens : t -> t           (* = enclose (lparen, rparen)     *)
  val angles : t -> t           (* = enclose (langle, rangle)     *)
  val braces : t -> t           (* = enclose (lbrace, rbrace)     *)
  val brackets : t -> t         (* = enclose (lbracket, rbracket) *)

  val spaces : int -> t

  val lparen : t    (* = txt "("  *)
  val rparen : t    (* = txt ")"  *)
  val langle : t    (* = txt "<"  *)
  val rangle : t    (* = txt ">"  *)
  val lbrace : t    (* = txt "{"  *)
  val rbrace : t    (* = txt "}"  *)
  val lbracket : t  (* = txt "["  *)
  val rbracket : t  (* = txt "]"  *)
  val pling : t     (* = txt "'"  *)
  val quote : t     (* = txt "\"" *)
  val semi : t      (* = txt ";"  *)
  val colon : t     (* = txt ":"  *)
  val comma : t     (* = txt ","  *)
  val space : t     (* = txt " "  *)
  val dot : t       (* = txt "."  *)
  val dash : t      (* = txt "-"  *)
  val sharp : t     (* = txt "#"  *)
  val percent : t   (* = txt "%"  *)
  val dollar : t    (* = txt "$"  *)
  val ampersand : t (* = txt "&"  *)
  val slash : t     (* = txt "/"  *)
  val backslash : t (* = txt "\\" *)
  val eq : t        (* = txt "="  *)
  val tilde : t     (* = txt "~"  *)
  val asterisk : t  (* = txt "*"  *)
  val bar : t       (* = txt "|"  *)

  val chr : char -> t
  val int : int -> t
  val real : real -> t
  val bool : bool -> t
  val option : ('a -> string) -> 'a option -> t
end
