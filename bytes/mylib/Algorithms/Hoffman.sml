structure Hoffman :> Hoffman =
struct
open General infix 2 $ infix 4 \< \> infix 5 ^* to

type bit = bool
datatype 'a codebook = T of 'a tree * 'a tree
                     | E of 'a vector

structure Codebook =
struct
fun create syms =
    let
      open Heap
      val h = Heap.fromList $ List.map (Pair.map (id, E)) syms
      fun loop h =
          let
            val ((f1, s1), h) = spliti h
            val ((f2, s2), h) = spliti h
          in
            loop $ insert h (f1 + f2, T (s1, s2))
          end handle Empty => h
    in
      loop h
    end

fun gen lvl vec =
    let
      fun collect n = map (fn i => Vector.slice (vec, i, SOME n))
                          (0 to Vector.length vec - n)
      fun eq x y =
          let open VectorSlice in
            length x = length y andalso
            let
              fun loop i =
                  i >= length x orelse
                  sub (x, i) = sub (y, i) andalso
                  loop (i + 1)
            in
              loop 0
            end
          end
      fun freqs nil = nil
        | freqs (sym :: syms) =
          let
            val (n, syms) = Pair.map (length, id) $ List.partition (eq sym) syms
          in
            (n, sym) :: freqs syms
          end
      fun prefix x y =
          let open VectorSlice in
            isEmpty x orelse
            sub (x, 0) = sub (y, 0) andalso
            prefix (subslice (x, 1, NONE)) (subslice (y, 1, NONE))
          end
      fun contains x y =
          let open VectorSlice in
            length x <= length y andalso
            prefix x y orelse
            contains x (subslice (y, 1, NONE))
          end
      val syms = List.tabulate (lvl, freqs o collect o 1 \< op+)
      fun prune nil = nil
        | prune (syms :: symss) =
          let
            val syms' = concat symss
            fun one (n, sym) = foldl (fn ((n', sym'), a) =>
                                         if contains sym sym' then
                                           a + 
end
end
