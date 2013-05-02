signature Parsing =
sig
  datatype 'a result =
           Unit
         | Lit of 'a
         | Cat of 'a result * 'a result
         | Inl of 'a result
         | Inr of 'a result
         | In of 'a result
  datatype 'a regex =
           Zero
         | One
         | Literal of 'a
         | ++ of 'a regex * 'a regex
         | ** of 'a regex * 'a regex
         | Star of 'a regex

  val alt : 'a regex list -> 'a regex
  val cat : 'a regex list -> 'a regex
  val valt : 'a vector -> 'a regex
  val vcat : 'a vector -> 'a regex
  val balance : 'a regex -> 'a regex

  type ('a, 'b) reader = 'b -> ('a * 'b) option
  type ('a, 'b) nondet_reader = 'b -> ('a * 'b) LazyList.t

  val scan : ''a regex -> (''a, 'b) reader -> (''a result, 'b) nondet_reader
  val scanAtomic : ''a regex -> (''a, 'b) reader -> (''a result, 'b) reader

  val parse : ''a regex -> ''a vector -> ''a result LazyList.t
  val atomic : ''a regex -> ''a vector -> ''a result option

  val flatten : 'a result -> 'a list
end
