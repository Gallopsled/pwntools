signature CList =
sig
  type 'a clist

  val empty : 'a clist
  val singleton : 'a -> 'a clist
  val @@ : 'a clist * 'a clist -> 'a clist

  val length : 'a clist -> int

  val fromList : 'a list -> 'a clist
  val toList : 'a clist -> 'a list
end
