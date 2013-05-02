structure SourceText :> SourceText =
struct
(* filename * (line lenght * line text) list *)
type t = File.t option * (int * string) list

exception SourceText of string

fun die msg = raise SourceText msg

fun fromFile f =
    let
      val is = File.openIn f
      fun lines () =
          case TextIO.inputLine is of
            SOME l =>
            let
              val l' = String.untabify (!String.TAB_WIDTH) l
            in
              (size l', l') :: lines ()
            end
          | NONE => nil
    in
      (SOME f, lines ()) before TextIO.closeIn is
    end

fun fromString s =
    (NONE, map (fn l =>
                   let
                     val l' = String.untabify (!String.TAB_WIDTH) l ^ "\n"
                   in
                     (size l', l')
                   end
               ) (String.fields (fn c => c = #"\n") s)
    )

fun reread (SOME f, _) = fromFile f
  | reread _ = die "Can't reread SourceText constructed from string."

fun write (SOME f, ls) =
    let
      val os = File.openOut f
    in
      app (fn (_, l) => TextIO.output (os, l)) ls
      before TextIO.closeOut os
    end
  | write _ = die "Can't write SourceText constructed from string."

fun getFile (SOME f, _) = f
  | getFile _ = die "SourceText constructed from string."

fun getSource (f, ls) pl pr =
    let
      fun drop nil _ = die "Left position after end of file in getSource."
        | drop ((s, l) :: ls) n =
          if pl > n + s then
            (* pl lies after end of this line *)
            drop ls (n + s)
          else
            take ((n + s - pl, String.extract (l, pl - n, NONE)) :: ls) pl
      and take nil _ = die "Right position after end of file in getSource."
        | take ((s, l) :: ls) n =
          if pr > n + s then
            (* pr lies after end of this line *)
            l :: take ls (n + s)
          else
            [String.substring (l, 0, pr - n)]
    in
      String.concat (drop ls 0)
    end

fun getSize (_, ls) = foldl (fn ((s, _), a) => s + a) 0 ls
fun getLines (_, ls) = length ls

fun patch (f, ls) pl pr sub =
    let
      val subs = String.fields (fn c => c = #"\n") sub
      fun seek nil _ = die "Left position after end of file in patch."
        | seek (ls' as ((s, l) :: ls)) n =
          if pl > n + s then
            (s, l) :: seek ls (n + s)
          else
            let
              val (sl, ll) = (s - pl + n, String.substring (l, 0, pl - n))
              val (sr, lr, ls) = drop ls' n
            in
              case subs of
                [sub] => (sl + sr + size sub, ll ^ sub ^ lr) :: ls
              | sub :: subs =>
                let
                  fun loop [sub] = (sr + size sub, sub ^ lr) :: ls
                    | loop (sub :: subs) = (size sub, sub) :: loop subs
                    | loop _ = die "patch.seek.loop"
                in
                  (sl + size sub, ll ^ sub) :: loop subs
                end
              | _ => die "patch.seek"
            end
      and drop nil _ = die "Right position after end of file in patch."
        | drop ((s, l) :: ls) n =
          if pr > n + s then
            drop ls (s + n)
          else
            (s - pr + n,
             String.extract (l, pr - n, NONE),
             ls)
    in
      (f, seek ls 0)
    end

fun patchLine (f, ls) l sub =
    let
      fun insert (_ :: ls) 0 = (size sub, sub) :: ls
        | insert (l :: ls) n = l :: insert ls (n - 1)
        | insert nil _ = die "No more lines in patchLine."
    in
      (f, insert ls l)
    end

fun makeReader (f, ls) =
    let
      val ls = ref ls
      fun reader _ =
          case !ls of
            nil => ""
          | (_, l) :: r => (ls := r ; l)
    in
      reader
    end

fun posToRowCol (_, ls) p =
    let
      fun loop ((n, _) :: ls) l p =
          if n > p then
            {row = l, column = p}
          else
            loop ls (l + 1) (p - n)
        | loop _ _ _ = die "Position outside file."
    in
      loop ls 1 p
    end

fun posToString st p =
    let
      val f = getFile st
      val {row = r, column = c} = posToRowCol st p
    in
      Path.toString f ^ ":" ^ Int.toString r ^ "." ^ Int.toString c
    end

fun showPos st = Layout.txt o posToString st

fun toString (_, ls) =
    String.concat (map (fn (_, l) => l) ls)
end
