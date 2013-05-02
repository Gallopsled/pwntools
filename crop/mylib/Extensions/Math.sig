signature Math =
sig
include MATH where type real = Real.real

(* faster than pow *)
val intpow : real * int -> real

val intsum : int list -> int
val realsum : real list -> real

val mean : real list -> real
val harmonicMean : real list -> real

(* TODO
 * val gcd : int list -> int
 * val lcm : int list -> int
 *)
end
