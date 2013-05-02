structure Benchmark :> Benchmark =
struct
val zeroTime = {usr = Time.zeroTime, sys = Time.zeroTime}
val dummyTimer = Timer.totalCPUTimer ()

val time = ref zeroTime
val time' = ref zeroTime
val timer = ref dummyTimer

fun ++ {usr = u1, sys = s1} =
    let
      val {usr = u2, sys = s2} = !time
    in
      time := {usr = Time.+ (u1, u2), sys = Time.+ (s1, s2)}
    end

fun start () = timer := Timer.startCPUTimer ()
fun pause () = (++ (Timer.checkCPUTimer (!timer)) ; time' := !time)
fun stop () = (pause () ; time := zeroTime)
fun restart () = (stop () ; start ())
fun time () =
    let
      val {usr, sys} = !time'
    in
      {usr = usr, sys = sys, tot = Time.+ (usr, sys)}
    end
fun show () =
    let
      val {usr, sys, tot} = time ()
    in
      "User: " ^ Time.toString usr ^ ", " ^
      "System: " ^ Time.toString sys ^ ", " ^
      "Total: " ^ Time.toString tot
    end

fun print "" = TextIO.print (show () ^ "\n")
  | print s = TextIO.print (s ^ "\n  " ^ show () ^ "\n")
fun stopAndPrint s = (stop () ; print s)
end
