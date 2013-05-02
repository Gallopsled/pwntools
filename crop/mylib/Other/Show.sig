signature Show =
sig
    val int : int -> string
    val real : real -> string
    val bool : bool -> string
    val char : char -> string
    val string : string -> string
    val option : ('a -> string) -> 'a option -> string
    val order : order -> string

    val pair : ('a -> string) ->
               ('b -> string) ->
               'a * 'b -> string
    val triple : ('a -> string) ->
                 ('b -> string) ->
                 ('c -> string) ->
                 'a * 'b * 'c -> string
    val quadruple : ('a -> string) ->
                    ('b -> string) ->
                    ('c -> string) ->
                    ('d -> string) ->
                    'a * 'b * 'c * 'd -> string

    val list : ('a -> string) -> 'a list -> string
end
