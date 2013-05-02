structure Lazy :> Lazy =
struct
type 'a thunk = unit -> 'a
datatype 'a t' = Thunk     of 'a thunk
               | Value     of 'a
               | Exception of exn
type 'a t = 'a t' ref

fun lazy f = ref (Thunk f)
fun eager v = ref (Value v)
fun force t =
    case !t of
      Thunk f =>
      (let
         val v = f ()
       in
         t := Value v ;
         v
       end
       handle e =>
              (t := Exception e;
               raise e)
      )
    | Value v => v
    | Exception e => raise e
fun delay t = lazy (fn _ => force (t ()))
end
