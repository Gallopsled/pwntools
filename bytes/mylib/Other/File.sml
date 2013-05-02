structure File :> File =
struct
type t = Path.t

structure FS = OS.FileSys

val size = Position.toInt o FS.fileSize o Path.path
val modtime = FS.modTime o Path.path

fun exists f = FS.access (Path.path f, nil)
fun readable f = FS.access (Path.path f, [FS.A_READ])
fun writable f = FS.access (Path.path f, [FS.A_WRITE])

val openIn = TextIO.openIn o Path.path
val openOut = TextIO.openOut o Path.path
val openAppend = TextIO.openAppend o Path.path

end
