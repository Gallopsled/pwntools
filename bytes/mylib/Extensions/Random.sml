structure Random :> Random =
struct
open Random

structure SelfSeed =
struct
val rand =
    let
      val is = TestIO.openIn "/dev/urandom"
