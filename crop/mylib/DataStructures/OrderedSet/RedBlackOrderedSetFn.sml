(* This deserves a reference to Chris Okasaki 1993 for the datatype, insert, member and balance funktions *)
(* Delete is implemented from Haskell code http://www.cs.kent.ac.uk/people/staff/smk/redblack/Untyped.hs *)

functor RedBlackOrderedSetFn (Element : Ordered) :>
        OrderedSet where type element = Element.t =
struct
    type element = Element.t

    datatype color = R | B
    datatype t = E
               | T of color * t * element * t

    fun die "" = raise Fail "Unimplemented"
      | die s = raise Fail s

    val empty = E

    fun singleton x = T (B, E, x, E)


    fun sub1 (T (B, l, y, r)) = T (R, l, y, r)
      | sub1 _ = die "Invariance violation"

    fun balance (T (R,  ll,                   ly,  lr))                    y (T (R, rl, ry,  rr))                                        = T (R, (T (B, ll,  ly,  lr)),   y, (T (B, rl,   ry,  rr)))
      | balance (T (R, (T (R, ll, lly, llr)), ly,  lr))                    y  r                                                          = T (R, (T (B, ll, lly, llr)),  ly, (T (B, lr,    y,   r)))
      | balance (T (R,  ll,                   ly, (T (R, lrl, lry, lrr)))) y  r                                                          = T (R, (T (B, ll,  ly, lrl)), lry, (T (B, lrr,   y,   r)))
      | balance  l                                                         y (T (R,  rl,                    ry, (T (R, rrl, rry, rrr)))) = T (R, (T (B,  l,   y,  rl)),  ry, (T (B, rrl, rry, rrr)))
      | balance  l                                                         y (T (R, (T (R, rll, rly, rlr)), ry,  rr))                    = T (R, (T (B,  l,   y, rll)), rly, (T (B, rlr,  ry,  rr)))
      | balance  l                                                         y  r = T (B, l, y, r)

    fun balanceLeft (T (R, ll, ly, lr)) y  r                                      = T (R, T (B, ll, ly, lr), y, r)
      | balanceLeft  l                  y (T (B, rl, ry, rr))                     = balance l y (T (R, rl, ry, rr))
      | balanceLeft  l                  y (T (R, (T (B, rll, rly, rlr)), ry, rr)) = T (R, (T (B, l, y, rll)), rly, (balance rlr ry (sub1 rr)))
      | balanceLeft _ _ _ = die "Invariance violation"

    fun app E r = r
      | app l E = l
      | app (T (R, ll, ly, lr)) (T (R, rl, ry, rr)) =
        (case app lr rl of
           T (R, l, y, r) => T (R, (T (R, ll, ly, l)), y, (T (R, r, ry, rr)))
         | x => T (R, ll, ly, (T (R, x, ry, rr)))
        )
      | app (T (B, ll, ly, lr)) (T (B, rl, ry, rr))  =
        (case app lr rl of
           T (R, l, y, r) => T (R, (T (B, ll, ly, l)), y, (T (B, r, ry, rr)))
         | x => balanceLeft ll ly (T (B, x, ry, rr))
        )
      | app l (T (R, rl, ry, rr))  = T (R, (app l rl), ry, rr)
      | app (T (R, ll, ly, lr)) r  = T (R, ll, ly, (app lr r))

    fun balanceRight  l                                      y (T (R, rl, ry, rr)) = T (R, l, y, (T (B, rl, ry, rr)))
      | balanceRight (T (B, ll, ly, lr))                     y  r                  = balance (T (R, ll, ly, lr)) y r
      | balanceRight (T (R, ll, ly, (T (B, lrl, lry, lrr)))) y  r                  = T (R, balance (sub1 ll) ly lrl, lry, T (B, lrr, y, r))
      | balanceRight _ _ _ = die "Invariance violation"

    fun insert s x =
        let
            fun insert' E = T (R, E, x, E)
              | insert' (s as T (B, l, y, r)) =
                (case Element.compare x y of
                   LESS    => balance (insert' l) y  r
                 | GREATER => balance l           y (insert' r)
                 | EQUAL   => s)
              | insert' (s as T (R, l, y, r)) =
                (case Element.compare x y of
                   LESS     => T (R, insert' l, y, r)
                 | GREATER  => T (R, l,         y, insert' r)
                 | EQUAL    => s)
        in
          case insert' s of
            T (_, l, x, r) => T (B, l, x, r)
          | _              => die "Impossible"
        end

    fun delete s x =
        let
          fun delete' E = E
            | delete' (T (_, l, y, r)) =
              case Element.compare x y of
                LESS => delFromLeft l y r
              | GREATER => delFromRight l y r
              | EQUAL => app l r

          and delFromLeft (l as T (B, _, _, _)) y r = balanceLeft (delete' l) y r
            | delFromLeft l y r = T (R, (delete' l), y, r)

          and delFromRight l y (r as T (B, _, _, _)) = balanceRight l y (delete' r)
            | delFromRight l y r = T (R, l, y, (delete' r))
        in
          case delete' s of
            T (_, l, y, r) => T (B, l, y, r)
          | _             =>  E
        end

    fun member E _ = false
      | member (T (_, l, y, r)) x =
        case Element.compare x y of
            LESS    => member l x
          | GREATER => member r x
          | EQUAL   => true


    val fromList = foldl (fn (x, s) => insert s x) empty

    fun foldl _ b E = b
      | foldl f b (T (_, l, x, r)) = foldl f (f (x, foldl f b l)) r

    val fold = foldl

    fun foldr _ b E = b
      | foldr f b (T (_, l, x, r)) = foldr f (f (x, foldr f b r)) l

    fun partition p = foldl (fn (x, (s, s')) =>
                                if p x then
                                    (insert s x, s')
                                else
                                    (s, insert s' x)
                            ) (empty, empty)
    fun filter p = foldl (fn (x, s) => if p x then insert s x else s) empty

    fun exists _ E = false
      | exists p (T (_, l, x, r)) = p x orelse exists p l orelse exists p r

    fun all _ E = true
      | all p (T (_, l, x, r)) = p x andalso all p l andalso all p r

    fun find _ E = NONE
      | find p (T (_, l, x, r)) =
        if p x then
            SOME x
        else
            case find p l of
                SOME x => SOME x
              | NONE => find p r

    val union = foldl (fn (e, s) => insert s e)

    fun inter s = filter (member s)

    val diff = foldl (fn (e, s) => delete s e)

    fun subset s = all (member s)

    fun isEmpty E = true
      | isEmpty _ = false


    fun compare E E = EQUAL
      | compare (T _) E = GREATER
      | compare E (T _) = LESS
      | compare (T (_, l, x, r)) (T (_, l', x', r')) =
        (* First compare the left part as this is always less than the node itself.
            If equal then compare the node itself.
              if equal then compare the right part as it is always greather than the node itself.

           If any is not equal then return the order returned by Element.compare *)
        case compare l l' of
          EQUAL => (case Element.compare x x' of
                      EQUAL => compare r r'
                    | x => x)
        | x => x


    fun toList t =
        let
          fun toList' E res = res
            | toList' (T (_, l, x, r)) res =  toList' l ( x :: (toList' r res))
        in
          toList' t []
        end

    fun equal E E = true
      | equal (T (_, l, x, r)) (T (_, l', y, r')) =
        (case Element.compare x y of
           EQUAL => equal l l' andalso equal r r'
         | _ => false)
      | equal _ _ = false

    fun card E = 0
      | card (T (_, l, _, r)) = 1 + card l + card r

    fun app _ E = ()
      | app f (T (_, l, x, r)) = (app f l ; f x ; app f r)

    fun mapPartial f t =
        let
          (* the tree is balanced on insert so the ordering of calling insert dosn't matter *)
          fun loop E res = res
            | loop (T (_, l, x, r)) res =
              (loop l o loop r)
                (case f x of
                   SOME x' => insert res x'
                 | NONE    => res)
        in
          (* Start with an empty tree as the result *)
          loop t empty
        end

    (* This is ugly, but it is easy and saves to copy almost the same code as in mapPartial.
       It only introduces a tiny overhead of "boxing" all values to SOME and then "de-boxing"
       them in mapPartial *)
    fun map f = mapPartial (SOME o f)

    fun least E = raise Empty
      | least (T (_, E, x, _)) = x
      | least (T (_, l, _, _)) = least l

    fun greatest E = raise Empty
      | greatest (T (_, _, x, E)) = x
      | greatest (T (_, _, _, r)) = greatest r


    fun splitLeast E = raise Empty
      | splitLeast t =
        let
          val n = least t
        in
          (n, delete t n)
        end

    fun splitGreatest E = raise Empty
      | splitGreatest t =
        let
          val n = greatest t
        in
          (n, delete t n)
        end

    val split = splitLeast


    fun some E = raise Empty
      | some (T (_, _, y, _)) = y

    fun toString p s =
        let
          val elems = toList s
          fun toString' (s::ss) = (p s) ^ (List.foldl (fn (a,b) => b ^ ", " ^ (p a)) "" ss)
            | toString' [] = ""
        in
          "{" ^ (toString' elems) ^ "}"
        end

    (*

      Currently shows the tree as this (when adding elements 0--10):

               [B|3]
     [B|1]                         [R|7]
[B|0]     [B|2]          [B|5]               [B|9]
                    [B|4]     [B|6]     [B|8]     [B|10]


      Expanding to show the tree as (would be nice):

       .-------[B|3]-----------------.
  .--[B|1---.              .-------[R|7]-------.
[B|0]     [B|2]       .--[B|5]--.         .--[B|9]--.
                    [B|4]     [B|6]     [B|8]     [B|10]

      Alternativelyt it would be easy to post edit the tree to look like this, by adding lines between,
      not adding the dog and finding start and end indexes of "---" to add / and \

        -------[B|3]-----------------
       /                             \
   --[B|1---                -------[R|7]-------
  /         \              /                   \
[B|0]     [B|2]        --[B|5]--           --[B|9]--
                      /         \         /         \
                    [B|4]     [B|6]     [B|8]     [B|10]
     *)

    (* fun show E = "E" *)
    (*   | show t = *)
    (*     let *)
    (*       fun genSpace 0 = "" *)
    (*         | genSpace n = " " ^ (genSpace (n-1)) *)

    (*       fun colorToString c = case c of R => "R" | B => "B" *)

    (*       (\* Invariant: We know that there is always a line if the node is not a *)
    (*          leaf (E). All T nodes has two leafs which generates empty lines at *)
    (*          minimum.  *\) *)
    (*       fun show' E                preSpace []                       = (preSpace, [(genSpace preSpace) ^ ""]) *)
    (*         | show' E                preSpace (thisLine :: linesBelow) = (preSpace, (thisLine ^ (genSpace (preSpace - (size thisLine))) ^ "") :: linesBelow) *)
    (*         | show' (T (c, l, y, r)) preSpace []                       = *)
    (*           let *)
    (*             val elem = "[" ^ (colorToString c) ^ "|" ^ (Element.toString y) ^ "]" *)
    (*             val elemLen = size elem *)

    (*             val (newPreSpaceLeft, newLinesLeft) = show' l preSpace [] *)
    (*             val newPreSpace  = newPreSpaceLeft + elemLen *)

    (*             val (newPreSpaceRight, newLinesRight) = show' r newPreSpace newLinesLeft *)
    (*           in *)
    (*             (newPreSpaceRight, ((genSpace newPreSpaceLeft) ^ elem) :: newLinesRight) *)
    (*           end *)
    (*         | show' (T (c, l, y, r)) preSpace (thisLine :: linesBelow) = *)
    (*           let *)
    (*             val elem = "[" ^ (colorToString c) ^ "|" ^ (Element.toString y) ^ "]" *)
    (*             val elemLen = size elem *)

    (*             val (newPreSpaceLeft, newLinesLeft) = show' l preSpace linesBelow *)
    (*             val newPreSpace = newPreSpaceLeft + elemLen *)

    (*             val (newPreSpaceRight, newLinesRight) = show' r newPreSpace newLinesLeft *)

    (*             val addSpace = newPreSpaceLeft - (size thisLine) *)
    (*           in *)
    (*             (newPreSpaceRight, (thisLine ^ (genSpace addSpace) ^ elem ) :: newLinesRight) *)
    (*           end *)

    (*       val lines = #2 (show' t 0 []) *)
    (*     in *)
    (*       List.foldl (fn (a, b) => b ^ a ^ "\n") "" lines *)
    (*     end *)
end
