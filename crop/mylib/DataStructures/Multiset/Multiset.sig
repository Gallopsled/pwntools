signature Multiset =
sig
    eqtype ''a multiset

    val empty : ''a multiset

    val insert : ''a multiset -> ''a -> ''a multiset
end

