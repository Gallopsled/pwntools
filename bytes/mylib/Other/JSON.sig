signature JSON =
sig
    datatype t = Object of t Dictionary.t
               | Array of t list
               | String of string
               | Number of real
               | Bool of bool
               | Null
    exception Match of t
    (* Description, JSON string, error location *)
    exception Parse of string * string * int

    (* Reads one JSON value. If the string contains more than a single JSON
     * value or is not in a valid JSON format the JSON.Parse exception is
     * raised.
     *)
    val read : string -> t

    (* Same as JSON.read, but can read multiple JSON values. If the string is
     * not in valid a valid JSON format the JSON.Parse exception is raised.  The
     * JSON values is not required to be seperated by whitespace, but sending
     * two numbers without whitespace between will result in them being read as
     * one
     *)
    val readMany : string -> t list

    (* Writes an SML representation of a JSON value (JSON.t) to a string. *)
    val write : t -> string

    (* Writes a list of JSON values (JSON.t) to a string seperated by newlines
     *)
    val writeMany : t list -> string

    (* An 'a converter ('a Converter.t) is something that converts values of
     * type 'a to JSON values (JSON.t) and vise versa.
     *
     * Some default converters are defined. New ones a build with
     * Converter.make. It takes to functions; one for the 'a -> json direction
     * and one for the json -> 'a direction. If a json value is given that
     * cannot be converted, the function should raise Match.
     *)
    structure Converter : sig
        type json
        type 'a t
        exception Match of json
        val make : {toJSON : 'a -> json, fromJSON : json -> 'a} -> 'a t
        val object : 'a t -> 'a Dictionary.t t
        val array : 'a t -> 'a list t
        val string : string t
        val number : real t
        val bool : bool t
        val null : unit t
        val json : json t
    end where type json = t

    (* Takes an 'a converter and a JSON string and returns the value
     * represented by that string. *)
    val from : 'a Converter.t -> string -> 'a

    (* Reads multiple values using a converter. *)
    val fromMany : 'a Converter.t -> string -> 'a list

    (* Writes a value using a converter. *)
    val to : 'a Converter.t -> 'a -> string

    (* Writes multiple values using a converter. The values are seperated by
       newlines. *)
    val toMany : 'a Converter.t -> 'a list -> string

    (* These can raise Match *)
    val dictionaryOf : t -> t Dictionary.t
    val listOf : t -> t list
    val stringOf : t -> string
    val realOf : t -> real
    val boolOf : t -> bool

    val ++ : t * t -> t

    val map : (t -> t) -> t -> t

    (* The mapped function returns a boolean value indicating wheter to break
     * (true) or continue (false) the map on the rest of the list *)
    (* val mapUntil : (t -> bool * t) -> t -> bool * t *)

    (* val foldl: (t * 'b -> 'b) -> 'b -> t -> 'b *)
    val fold : (t * 'b -> 'b) -> 'b -> t -> 'b

    (* val filter : (t -> bool) -> t -> t *)
    (* val filterUntil : (t -> bool) -> t -> (bool * t) *)

    (* val exists : (t -> bool) -> t -> bool *)

    (* Pretty print the JSON code. Usefull for debug or writing the json to a
     * file *)
    val show : t -> string
end
