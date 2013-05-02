structure Log :> Log =
struct
datatype level = Debug
               | Verbose
               | Chatty
               | Normal
               | Quiet

val level = ref Normal
val ind = ref 0

fun setLevel l = level := l

fun setIndentation n = ind := n

fun indent n = ind := (!ind + n)

fun print s = if !ind > 0
              then println (String.spaces (!ind) ^ s)
              else println s

fun debug s =
    if !level = Debug
    then print s
    else ()

fun verbose s =
    if !level = Verbose
    then print s
    else debug s

fun chatty s =
    if !level = Chatty
    then print s
    else verbose s

fun normal s =
    if !level <> Quiet
    then print s
    else ()

fun warning s =
    (TextIO.output (TextIO.stdErr,
                    if !level = Quiet
                    then s ^ "\n"
                    else String.spaces (!ind) ^ s ^ "\n"
                   )
   ; TextIO.flushOut TextIO.stdErr)
end
