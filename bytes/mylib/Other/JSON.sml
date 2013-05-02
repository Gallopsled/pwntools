structure JSON :> JSON =
struct
datatype t = Object of t Dictionary.t
           | Array of t list
           | String of string
           | Number of real
           | Bool of bool
           | Null

exception Parse of string * string * int
exception Match of t

fun die s = Debug.error ("JSON: " ^ s)

fun dictionaryOf (Object dict) = dict
  | dictionaryOf x = raise Match x

fun listOf (Array lst) = lst
  | listOf x = raise Match x

fun stringOf (String s) = s
  | stringOf x = raise Match x

fun realOf (Number n) = n
  | realOf x = raise Match x

fun boolOf (Bool n) = n
  | boolOf x = raise Match x

fun readOne (s, i) =
    let
      fun fail i e = raise Parse (e, s, i)
      fun endof i t =
          raise Parse ("End of JSON while reading " ^ t ^ ".", s, i)
      fun at i = String.sub (s, i)
      fun substring (i, j) = String.substring (s, i, j)

      fun skipWhitespace i =
          let
            val i = i + 1
          in
            if Char.isSpace (at i) then
              skipWhitespace (i + 1)
            else
              i
          end handle Subscript => i

      (* Invariant: All read functions skip trailing whitespace *)
      fun rValue i =
          let
            val c = at i
            val i' = skipWhitespace i
          in
            if c = #"{" then
              rObject i'
            else if c = #"[" then
              rArray i'
            else if c = #"\"" then
              rString i'
            else if Char.contains "-0123456789" c then
              rNumber i'
            else
              rBoolOrNull i'
          end handle Subscript => endof i "value"

      and rObject i =
          let
            fun rPair i =
                let
                  val (l, i) = rString i
                  val l = stringOf l
                in
                  if at i = #":" then
                    let
                      val (v, i) = rValue (skipWhitespace i)
                    in
                      ((l, v), i)
                    end
                  else
                    fail i "Expected colon in object."
                end
            fun loop (d, i) =
                let
                  val (p, i) = rPair i
                  val d = case Dictionary.insert d p of
                            SOME d => d
                          | NONE => fail i "Identical labels in object."
                in
                  case at i of
                    #"," => loop (d, skipWhitespace i)
                  | #"}" => (d, skipWhitespace i)
                  | _ => fail i "Expected comma or } in object."
                end
            val (d, i) =
                if at i = #"}" then
                  (Dictionary.empty, skipWhitespace i)
                else
                  loop (Dictionary.empty, i)
          in
            (Object d, i)
          end handle Subscript => endof i "object"

      and rArray i =
          let
            fun loop i =
                let
                  val (v, i) = rValue i
                in
                  case at i of
                    #"," =>
                    let
                      val (l, i) = loop (skipWhitespace i)
                    in
                      (v :: l, i)
                    end
                  | #"]" => ([v], skipWhitespace i)
                  | _ => fail i "Expected comma or ] in array."
                end
            val (l, i) =
                if at i = #"]" then
                  (nil, skipWhitespace i)
                else
                  loop i
          in
            (Array l, i)
          end handle Subscript => endof i "array"

      and rString i =
          let
            exception NotHex
            fun charToInt c =
                if Char.isDigit c then
                  ord c - ord #"0"
                else if Char.isUpper c then
                  ord c - ord #"A" + 10
                else if Char.isLower c then
                  ord c - ord #"a" + 10
                else
                  raise NotHex

            fun charsToInt base s =
                foldl (fn (c, a) => a * base + charToInt c) 0 (explode s)

            fun rChar i =
                let
                  val c = at i
                in
                  if c = #"\\" then
                    case at (i + 1) of
                      #"\"" => (#"\"", i + 2)
                    | #"\\" => (#"\\", i + 2)
                    | #"b"  => (#"\b", i + 2)
                    | #"f"  => (#"\f", i + 2)
                    | #"n"  => (#"\n", i + 2)
                    | #"r"  => (#"\r", i + 2)
                    | #"t"  => (#"\t", i + 2)
                    | #"u"  =>
                      let
                        val c = charsToInt
                                  16
                                  (substring (i + 2, 4))
                      in
                        if c > 255 then
                          fail i "Only unicode characters in range 0--255 supported."
                        else
                          (chr c, i + 6)
                      end
                    | _ => fail i "Unexpected escape character."
                  else
                    (c, i + 1)
                end
                handle Subscript => endof i "character"
                     | NotHex    =>
                       fail i "Expected [0-9a-fA-F] in unicode escape."

            fun loop i =
                if at i = #"\"" then
                  (nil, skipWhitespace i)
                else
                  let
                    val (c, i) = rChar i
                    val (s, i) = loop i
                  in
                    (c :: s, i)
                  end

            val (s, i) = loop i
          in
            (String (implode s), i)
          end handle Subscript => endof i "string"

      and rNumber cs =
          let
            fun next i = SOME (at i, i + 1)
          in
            (* Hack: Real.scan doesn't force a digit *)
            (* in front of the decimal point.        *)
            case Real.scan next i of
              SOME (n, i) => (Number n, skipWhitespace (i - 1))
            | NONE => fail i "Not a number."
          end handle Subscript => endof i "number"

      and rBoolOrNull i =
          (if substring (i, 4) = "true" then
             (Bool true, skipWhitespace (i + 3))
           else if substring (i, 4) = "null" then
             (Null, skipWhitespace (i + 3))
           else if substring (i, 5) = "false" then
             (Bool false, skipWhitespace (i + 4))
           else
             fail i "Neither a boolean value nor null."
          ) handle Subscript => endof i "boolean or null"
    in
      rValue i
    end

fun read s =
    let
      val (v, i) = readOne (s, 0)
    in
      if i = size s then
        v
      else
        raise Parse ("Not a JSON value.", s, 0)
    end

fun readMany s =
    let
      val ss = size s
      fun loop i =
          let
            val (v, i) = readOne (s, i)
          in
            if i = ss then
              [v]
            else
              v :: loop i
          end
    in
      loop 0
    end

fun write (Object d) =
    let
      fun wPair (k, v) = "\"" ^ k ^ "\": " ^ write v
      fun loop [p] = wPair p
        | loop (p :: ps) = wPair p ^ ", " ^ loop ps
        | loop nil = ""
    in
      "{" ^ loop (Dictionary.toList d) ^ "}"
    end
  | write (Array l) =
    let
      fun loop [v] = write v
        | loop (v :: vs) = write v ^ ", " ^ loop vs
        | loop nil = ""
    in
      "[" ^ loop l ^ "]"
    end
  | write (String s) = "\"" ^ s ^ "\""
  | write (Number n) =
    if n < 0.0 then
      "-" ^ Real.toString (~n)
    else
      Real.toString n
  | write (Bool b) = Bool.toString b
  | write Null = "null"

fun writeMany nil = ""
  | writeMany [v] = write v
  | writeMany (v :: vs) = write v ^ "\n" ^ writeMany vs

fun from (f, _) = f o read
fun fromMany (f, _) = map f o readMany
nonfix to
fun to (_, t) = write o t
fun toMany (_, t) = writeMany o map t

structure Converter =
struct
type json = t
type 'a t = (json -> 'a) * ('a -> json)

exception Match of json

fun make {toJSON, fromJSON} = (fromJSON, toJSON)

fun object (f, t) =
    (fn Object d => Dictionary.map f d
      | x => raise Match x
   , fn d => Object (Dictionary.map t d)
    )

fun array (f, t) =
    (fn Array l => map f l
      | x => raise Match x
   , fn l => Array (map t l)
    )

val string =
    (fn String s => s
      | x => raise Match x
   , fn s => String s
    )

val number =
    (fn Number n => n
      | x => raise Match x
   , fn n => Number n)

val bool =
    (fn Bool b => b
      | x => raise Match x
   , fn b => Bool b
    )

val null =
    (fn Null => ()
      | x => raise Match x
   , fn () => Null
    )

val json =
    (fn x => x
   , fn x => x
    )
end

fun ++ (Array l, Array r) = Array (l @ r)
  | ++ (Object l, Object r) = Object (Dictionary.plus l r)
  | ++ (Array l, r) = Array (l @ [r])
  | ++ (l, Array r) = Array (l :: r)
  | ++ (l, r) = Array [l, r]

fun map f (Array lst) = Array (List.map (map f) lst)
  | map f (Object d) = Object (Dictionary.map (map f) d)
  | map f x = f x

fun fold f b (Array xs) = List.foldl (fn (x, b) => fold f b x) b xs
  | fold f b (Object xs) = Dictionary.foldl (fn (x, b) => fold f b x) b xs
  | fold f b x = f (x, b)

fun show x = write x
end
