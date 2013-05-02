structure Arrow :> Arrow =
struct
infix 4 ** && ++ ||
infix 3 >> <<
type ('a, 'b) t = 'a -> 'b

val const = General.const
val \< = General.\<
val \> = General.\>
val flip = General.flip
val id = General.id

fun first a (x, y) = (a x, y)
fun second a (x, y) = (x, a y)

fun (a ** b) (x, y) = (a x, b y)

fun (a && b) x = (a x, b x)

fun (a ++ b) z =
    case z of
      Either.Left x  => Either.Left (a x)
    | Either.Right y => Either.Right (b y)

fun left a = a ++ id
fun right a = id ++ a

fun (a || b) z =
    case (a ++ b) z of
      Either.Left x  => x
    | Either.Right y => y

fun (a >> b) = b o a
fun (a << b) = a o b
end
