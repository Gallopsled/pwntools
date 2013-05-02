structure Math :> Math =
struct
open Math

fun intpow (a : real, b) =
    (* 50 was determined by experimentation *)
    if b < 50 then
      let
        fun loop (a, 0) = a
          | loop (a, b) = a * loop (a, b - 1)
      in
        loop (a, b)
      end
    else
      let
        fun loop (a, b) =
            let
              val b' = b div 2
              val p = intpow (a, b')
            in
              if b mod 2 = 0 then
                p * p
              else
                a * p * p
            end
      in
        loop (a, b)
      end

fun mean xs =
    let
      val l = real (length xs)
    in
      foldl (fn (x, a) => x / l + a) 0.0 xs
    end

fun harmonicMean xs =
    let
      val l = real (length xs)
    in
      l / foldl (fn (x, a) => 1.0 / x + a) 0.0 xs
    end

val intsum = foldl op+ 0
val realsum = foldl op+ 0.0
end
