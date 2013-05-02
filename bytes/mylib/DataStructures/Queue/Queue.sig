

signature Queue =
sig
    type 'a t

    val empty      : 'a t
    val push       : 'a t -> 'a -> 'a t
    val pushList   : 'a t -> 'a list -> 'a t
    val append     : 'a t -> 'a t -> 'a t
    val isEmpty    : 'a t -> bool
    val size       : 'a t -> int
    val pop        : 'a t -> 'a t
    val peek       : 'a t -> 'a

    val toString   : ('a -> string) -> 'a t -> string
end
