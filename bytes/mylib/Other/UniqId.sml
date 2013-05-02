structure UniqId : UniqId =
struct
    (* Fair WARNING: I pulled this out of my ***
     *)
    local
      val s = Time.toSeconds $ Time.now ()
      val p = 3571
      val q = 2011
      val seed = ref $ LargeInt.toInt $ LargeInt.mod (s, LargeInt.fromInt q)
    in
    fun gen A n =
        let
          val m = size A
          fun loop 0 = nil
            | loop n =
              (seed := !seed * p mod q
             ; String.sub (A, !seed mod m) :: loop (n - 1)
              )
        in
          implode $ loop n
        end
    end

    fun next _ = gen "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" 10
end
