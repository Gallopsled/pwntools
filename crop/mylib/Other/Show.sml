structure Show =
struct
    val int = Int.toString
    val real = Real.toString
    val bool = Bool.toString
    fun char c = "#\"" ^ str c ^ "\""
    fun string s = "\"" ^ s ^ "\""

    fun option _ NONE = "NONE"
      | option show (SOME x) = "SOME(" ^ show x ^ ")"

    fun order LESS = "LESS"
      | order EQUAL = "EQUAL"
      | order GREATER = "GREATER"

    fun pair showa showb (a, b) = "(" ^ showa a ^ ", " ^ showb b ^ ")"
    fun triple showa showb showc (a, b, c)  = "(" ^ showa a ^ ", " ^ showb b ^ ", " ^ showc c ^ ")"

    fun quadruple showa showb showc showd (a, b, c, d) =
        "(" ^ showa a ^ ", " ^ showb b ^ ", " ^
        showc c ^ ", " ^ showd d ^ ")"

    fun list show xr =
        let
            fun list' nil = ""
              | list' [x] = show x
              | list' (x :: xr) = show x ^ ", " ^ list' xr
        in
            "[" ^ list' xr ^ "]"
        end
end
