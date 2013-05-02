structure Parsing :> Parsing =
struct
open General Lazy infixr 2 $ infix 4 \< \> infix 5 ^* to
open LazyList infix 5 @

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
         (* | Dot *)

  fun alt (r :: rs) = List.foldl (flip ++) r rs
    | alt _ = Zero
  fun cat (r :: rs) = List.foldl (flip **) r rs
    | cat _ = One
  fun valt ls =
      case VectorSlice.getItem $ VectorSlice.full $ Vector.map Literal ls of
        SOME (l, ls) => VectorSlice.foldl (flip ++) l ls
      | NONE => Zero
  fun vcat ls =
      case VectorSlice.getItem $ VectorSlice.full $ Vector.map Literal ls of
        SOME (l, ls) => VectorSlice.foldl (flip **) l ls
      | NONE => One
  fun balance r = r

  type ('a, 'b) reader = 'b -> ('a * 'b) option
  type ('a, 'b) nondet_reader = 'b -> ('a * 'b) LazyList.t

  fun scan r reader stream =
      let
        open Either
        datatype 'a t =
                 Z
               | O
               | L of 'a
        datatype 'a u' =
                 P of 'a u * 'a u
               | T of 'a u * 'a u
               | S of 'a u
        withtype 'a u = ('a t, int * 'a u') either
        fun ann r =
            let
              val regs = ref Map.empty
              fun id r =
                  case Map.lookup (!regs) r of
                    SOME i => i
                  | NONE   =>
                    let
                      val i = Map.size (!regs)
                    in
                      i before regs := Map.update (!regs) (r, i)
                    end
              fun loop r =
                  case r of
                    Zero => Left Z
                  | One  => Left O
                  | Literal l => Left $ L l
                  | ++ (r1, r2) => Right $ (id r, P (loop r1, loop r2))
                  | ** (r1, r2) => Right $ (id r, T (loop r1, loop r2))
                  | Star r' => Right $ (id r, S (loop r'))
            in
              (loop r, Map.size (!regs))
            end

        val (r, n) = ann r
        val dyn = Array.tabulate (n, fn _ => IntMap.empty)
        val pm = ref 0

        fun loop (r, p, s) =
            (* (if p > !pm then print $ Int.toString p ^ "\n" before pm := p else () ; *)
            case r of
              Left r =>
              (case r of
                 Z => eager nil
               | O => singleton (Unit, p, s)
               | L l =>
                 (case reader s of
                    SOME (l', s') =>
                    if l = l' then
                      singleton (Lit l, p + 1, s')
                    else
                      eager nil
                  | NONE          => eager nil)
              )
            | Right (i, r') =>
              (* case IntMap.lookup (Array.sub (dyn, i)) p of *)
              (*   SOME ps => ps before print $ "[Got lucky at " ^ Int.toString p ^ "]\n" *)
              (* | NONE    => *)
              (*   let *)
              (*     val ps = *)
                      case r' of
                        P (r1, r2) =>
                        map (fn (r, p, s) =>
                                (Inl r, p, s)) (loop (r1, p, s)) @
                        map (fn (r, p, s) =>
                                (Inr r, p, s)) (delay (fn _ => loop (r2, p, s)))
                      | T (r1, r2) =>
                        concat
                          (map (fn (r1, p, s) =>
                                   map (fn (r2, p, s) =>
                                           (Cat (r1, r2), p, s)
                                       ) $ loop (r2, p, s)
                               ) $ loop (r1, p, s)
                          )
                      | S r' =>
                        concat
                          (map (fn (r', p, s) =>
                                   map (fn (r, p, s) =>
                                           (Cat (r', r), p, s)
                                       ) $ loop (r, p, s)
                               ) $ loop (r', p, s)
                          ) @ singleton (Unit, p, s)
            (*     in *)
            (*       Array.update *)
            (*         (dyn, *)
            (*          i, *)
            (*          IntMap.update (Array.sub (dyn, i)) (p, ps) *)
            (*         ) ; *)
            (*       ps *)
            (*     end *)
            (* ) *)
      in
        map (fn (r, _, s) => (r, s)) $ loop (r, 0, stream)
      end

  fun scanAtomic r reader stream =
      SOME o hd $ scan r reader stream
      handle Empty => NONE

  fun parse r v =
      mapPartial
        (fn (r, s) =>
            if VectorSlice.length s = 0 then
              SOME r
            else
              NONE
        ) $ scan r VectorSlice.getItem (VectorSlice.full v)

  fun atomic r v =
      let
        exception Backtrack of int
        fun loop (r, p) =
            case r of
              Zero      => raise Backtrack p
            | One       => (Unit, p)
            | Literal l =>
              if p < Vector.length v andalso l = Vector.sub (v, p) then
                (Lit l, p + 1)
              else
                raise Backtrack p
            | ++ (r1, r2) => (Pair.map (Inl, id) $ loop (r1, p)
                              handle Backtrack _ => Pair.map (Inr, id) $ loop (r2, p))
            | ** (r1, r2) =>
              let
                val (r1, p) = loop (r1, p)
                val (r2, p) = loop (r2, p)
              in
                (Cat (r1, r2), p)
              end
            | Star r' =>
              let
                val (r', p) = loop (r', p)
                val (r, p) = loop (r, p)
              in
                (Cat (r', r), p)
              end handle Backtrack _ => (Unit, p)
      in
        SOME $ Pair.fst $ loop (r, 0) handle Backtrack p => NONE before print $ Int.toString p ^ "\n"
      end

  fun flatten r =
      case r of
        Unit => nil
      | Lit l => [l]
      | Cat (r1, r2) => List.@ (flatten r1, flatten r2)
      | Inl r => flatten r
      | Inr r => flatten r
      | In r => flatten r
end
