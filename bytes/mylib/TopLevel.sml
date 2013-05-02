val id = General.id
val const = General.const
val flipc = General.flipc
val flip = General.flip
val \< = General.\<
val \> = General.\>
val ^* = General.^*
val $ = General.$
val <- = String.<-
val curry = General.curry
val uncurry = General.uncurry
val pair = General.pair
val curry3 = General.curry3
val uncurry3 = General.uncurry3
val triple = General.triple
val curry4 = General.curry4
val uncurry4 = General.uncurry4
val quadruple = General.quadruple
val to = General.to
val inc = General.inc
val dec = General.dec
infix 5 ^* to <-
infix 4 \< \>
infixr 3 $

val println = TextIO.println
val system = OS.Process.system
val exit = OS.Process.exit
val ltoi = Int.fromLarge
val itol = Int.toLarge

datatype either = datatype Either.t
exception Either = Either.Either
val ofLeft = Either.ofLeft
val ofRight = Either.ofRight
(* val lefts = Either.lefts *)
(* val rights = Either.rights *)
val either = Either.either

(* val first = Arrow.first *)
(* val second = Arrow.second *)
(* val ** = Arrow.** *)
(* val && = Arrow.&& *)
(* val left = Arrow.left *)
(* val right = Arrow.right *)
(* val ++ = Arrow.++ *)
(* val || = Arrow.|| *)
(* val >> = Arrow.>> *)
(* val << = Arrow.<< *)
(* val loop = Arrow.loop *)
(* infix 4 ** && ++ || *)
(* infix 3 << >> *)

val fst = Pair.fst
val snd = Pair.snd
