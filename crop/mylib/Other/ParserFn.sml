functor ParserFn (Base : ParserBase) :>
        Parser where type ('a, 'b) result = ('a, 'b) Base.result
                 and type position = Base.position =
struct
open Base
infix 0 |||
infix 1 --- |-- --| ^^^ ::: @@@
infix 2 >>> --> ??? produce underlies

fun p >>> f = (p --> return o f)
fun liftP f = any >>> f
fun (p1 --- p2) = p1 --> (fn a => p2 --> return o pair a)
fun (p1 ^^^ p2) = p1 --> (fn a => p2 --> (fn b => return (a ^ b)))
fun (p1 --| p2) = p1 --> (fn x => p2 --> (fn _ => return x))
fun (p1 |-- p2) = p1 --> (fn _ => p2 --> (fn x => return x))
fun p produce x = p |-- return x
fun p1 ::: p2 = p1 --> (fn x => p2 --> (fn xs => return (x :: xs)))
fun p1 @@@ p2 = p1 --> (fn xs => p2 --> (fn ys => return (xs @ ys)))

fun void p = p |-- return ()

fun match p c = (try p ||| any |-- match p) c

fun predicate p =
    try (any -->
             (fn x =>
                 if p x then
                   return x
                 else
                   fail
             )
        )

fun lookAhead p =
    getState --> (fn state =>
    p --> (fn x =>
      setState state |-- return x
    ))

fun eof c = (notFollowedBy any ??? "end of stream") c

fun token t = predicate $ curry op= t
fun except t = predicate $ curry op<> t

fun (lexer underlies parser) c = parser $ lexer c

fun choice [p] = p
  | choice (p :: ps) = p ||| choice ps
  | choice _ = (any |-- fail) ??? "at least one parser in choice"

fun cons p = p >>> op::

fun link ps = foldr (cons o op---) (return nil) ps
fun count 0 p = return nil
  | count n p = cons (p --- count (n - 1) p)

fun many' p ? = ((try p |-- many' p) ||| return ()) ?
fun many1' p = p |-- many' p

fun many p c = (cons (try p --- many p) ||| return nil) c
fun many1 p = cons (p --- many p)
fun maybe p = p >>> SOME ||| return NONE
fun between l r p = l |-- p --| r
fun followedBy p = lookAhead p produce ()
fun manyTill p stop ? = (stop produce nil |||
                         cons (p --- manyTill p stop)) ?
fun sepBy1 p sep = cons (p --- many (sep |-- p))
fun sepBy p sep = sepBy1 p sep ||| return nil
fun endBy p e = many (p --| e)
fun endBy1 p e = many1 (p --| e)
fun sepEndBy p sep = sepBy p sep --| maybe sep
fun sepEndBy1 p sep = sepBy1 p sep --| maybe sep

fun chainl1 p oper =
    let
      fun rest lhs =
          (oper --- p) --> (fn (f, rhs) => rest $ f (lhs, rhs)) ||| return lhs
    in
      p --> rest
    end
fun chainl p oper x = chainl1 p oper ||| return x

fun chainr1 p oper =
    let
      fun scan c = (p --> rest) c
      and rest lhs =
          (oper --- scan) >>> (fn (f, rhs) => f (lhs, rhs)) ||| return lhs
    in
      scan
    end
fun chainr p oper x = chainr1 p oper ||| return x

structure Text =
struct
fun char c = token c ??? ("'" ^ str c ^ "'")

(* I actually wrote this - refactor please *)
fun string s =
    let
      fun loop nil = return nil
        | loop (c :: cs) = cons (char c --- loop cs) ???
                           ("'" ^ str c ^ "' in \"" ^ s ^ "\"")
    in
      loop (explode s) >>> implode
    end

fun oneOf cs = foldr op||| fail $ List.map char $ explode cs
fun noneOf cs = predicate (fn c => List.all (c \< op<>) $ explode cs)
                          ??? "a character not among \"" ^ String.toString cs ^ "\""
fun space c = (predicate Char.isSpace ??? "space") c
fun spaces c = (many space >>> length) c
fun newline c = (token #"\n" ??? "new line") c
fun tab c = (token #"\t" ??? "tab") c
fun upper c = (predicate Char.isUpper ??? "upper case letter") c
fun lower c = (predicate Char.isLower ??? "lower case letter") c
fun alphaNum c = (predicate Char.isAlphaNum ??? "alphanumeric character") c
fun letter c = (predicate Char.isAlpha ??? "letter") c
fun word c = (many1 letter >>> implode ??? "word") c
fun line c =
    ((newline produce nil ||| many1 $ except #"\n" --| maybe newline)
       >>> implode
       ??? "line"
    ) c
fun digit c = (predicate Char.isDigit ??? "digit") c
fun num c = (many1 digit >>> implode) c
fun whitespace c = ((many $ oneOf " \n\t\r") produce ()) c
fun strings ss =
    let
      fun cmp (x :: _) (y :: _) = x = y
        | cmp _ _ = false
      fun loop css =
          let
            val gs = List.group cmp css
            val (p, d) =
                foldr (fn (g, (p, d)) =>
                          let
                            val pc =
                                (token $ hd $ hd g) --- (loop $ map tl g)
                          in
                            (cons pc ||| p, d)
                          end
                      handle Empty => (p, true)
                      )
                      (fail, false)
                      gs
          in
            if d then p ||| return nil else p
          end
    in
      loop (map explode ss) >>> implode ??? "keyword"
    end

fun maybe p = p ||| return ""

end

structure RegEx =
struct
type 'a match = 'a LazyList.t
type ('a, 'x) regex = ('a, 'a match, 'x) parser

infix @ ** ++
open LazyList

fun class p =
    any -->
        (fn t =>
            if p t then
              return $ singleton t
            else
              fail
        )

fun zero c = (return $ eager nil) c

fun one c = (any >>> singleton) c
fun lit t = class $ t \< op=
fun oneOf ts = class (fn t => List.exists (t \< op=) ts)
fun noneOf ts = class (fn t => List.all (t \< op<>) ts)

fun run r = r >>> force

fun r1 ** r2 = (r1 --- r2) >>> op@
fun r1 ++ r2 = try r1 ||| r2

fun maybe r = try r ||| zero

fun star r c = (try (r ** star r) ||| zero) c

fun plus p = p ** star p

fun seq (t :: ts) = lit t ** seq ts
  | seq nil = zero

fun lower c = class Char.isLower c
fun upper c = class Char.isUpper c
fun digit c = class Char.isDigit c
fun letter c = class Char.isAlpha c
fun alphaNum c = class Char.isAlphaNum c
fun space c = class Char.isSpace c
end

structure Symb =
struct
fun lparen c = Text.char #"(" c
fun rparen c = Text.char #")" c
fun langle c = Text.char #"<" c
fun rangle c = Text.char #">" c
fun lbrace c = Text.char #"{" c
fun rbrace c = Text.char #"}" c
fun lbracket c = Text.char #"[" c
fun rbracket c = Text.char #"]" c
fun pling c = Text.char #"'" c
fun quote c = Text.char #"\"" c
fun semi c = Text.char #";" c
fun colon c = Text.char #":" c
fun comma c = Text.char #"," c
fun space c = Text.char #" " c
fun dot c = Text.char #"." c
fun dash c = Text.char #"-" c
fun hash c = Text.char #"#" c
fun percent c = Text.char #"%" c
fun dollar c = Text.char #"$" c
fun ampersand c = Text.char #"&" c
fun slash c = Text.char #"/" c
fun backslash c = Text.char #"\\" c
fun eq c = Text.char #"=" c
fun tilde c = Text.char #"~" c
fun asterisk c = Text.char #"*" c
end

structure Lex =
struct
fun lexeme p = p --| Text.whitespace

fun symbol s = lexeme $ Text.string s

fun identifier {head, tail} =
    lexeme ((head --- many tail) >>> op:: >>> implode)

fun letter c = lexeme Text.letter c

fun word c = lexeme Text.word c

fun keywords ks =
    foldr op||| fail $ List.map (fn (k, a) => try (symbol k) produce a)
    (rev $ List.sort (fn a => fn b => String.compare (fst a, fst b)) ks)

fun parens p = between (symbol "(") (symbol ")") p
fun braces p = between (symbol "{") (symbol "}") p
fun angles p = between (symbol "<") (symbol ">") p
fun brackets p = between (symbol "[") (symbol "]") p
fun semi c = symbol ";" c
fun colon c = symbol ":" c
fun comma c = symbol "," c
fun dot c = symbol "." c
fun semiSep p = sepBy p (symbol ";")
fun semiSep1 p = sepBy1 p (symbol ";")
fun commaSep p = sepBy p (symbol ",")
fun commaSep1 p = sepBy1 p (symbol ",")
end

structure Parse =
struct
fun run p r s = fst $ parse p r s

fun vector p v =
    fst $ parse p VectorSlice.getItem $ VectorSlice.full v

fun string p s =
    fst $ parse p Substring.getc $ Substring.full s

fun list p l = fst $ parse p List.getItem l

fun lazyList p l = fst $ parse p LazyList.getItem l

fun file p f = lazyList p $ LazyList.fromFile f

fun testVector show p v =
    test show p VectorSlice.getItem $ VectorSlice.full v

fun testString p s =
    test (fn c => "'" ^ str c ^ "'") p Substring.getc $ Substring.full s

fun testList show p l =
    test show p List.getItem l

fun testLazyList show p l =
    test show p LazyList.getItem l

fun testFile p f =
    testLazyList (fn c => "'" ^ str c ^ "'") p $ LazyList.fromFile f

end
end
