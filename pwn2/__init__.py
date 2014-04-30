# decide if we should behave like a lib (import pwn.lib / from pwn import lib)
# or not (import pwn / from pwn import *)
libmode = True

# if we're running in a REPL we need to know that, because overwriting sys.stdin
# will probably mess something up
hasrepl = False

# this will be set iff we're *not* in lib-mode *and* sys.stdout or sys.stderr is
# a TTY
hasterm = False
def closure ():
    global libmode, hasrepl
    import sys

    mods = sys.modules.keys()
    for repl in ['IPython', 'bpython', 'dreampielib']:
        if repl in mods:
            hasrepl = True

    # raise exception to set sys.exc_info so we can unwind the call stack
    try:
        raise BaseException
    except BaseException:
        frame = sys.exc_info()[2].tb_frame
    # go two frames up (current and `closure()')
    for _ in range(2):
        frame = frame.f_back
    if frame is None:
        # we have been called directly (which does not make sense)
        return

    filename = frame.f_code.co_filename
    if filename in ['<string>', '<stdin>']:
        # someone wrote `exec("import pwn...")' or python -c "import pwn..."
        # or we're running in the REPL

        # if we're in the REPL we need to know that because it does not rely on
        # sys.stdin.readline for user input
        hasrepl = filename == '<stdin>'

        # lets try to dissamble the code that imported us
        code = frame.f_code.co_code
        names = frame.f_code.co_names
        # first let see if our name is in there at all
        if __name__ not in names:
            return
        try:
            import opcode
            i = 0
            l = len(code)
            while i < l:
                op = ord(code[i])
                i += 1
                if op == opcode.opmap['IMPORT_NAME']:
                    # ignore extended args; this is a long shot anyway
                    arg = ord(code[i]) + (ord(code[i + 1]) << 8)
                    mod = names[arg]
                    # look one op ahead to see if it was 'from ... import ...'
                    i += 3
                    op = ord(code[i - 1])
                    if op == opcode.opmap['IMPORT_FROM']:
                        arg = ord(code[i]) + (ord(code[i + 1]) << 8)
                        what = names[arg]
                    else:
                        what = None
                    if mod == __name__:
                        libmode = what == 'lib'
                        break
                if op >= opcode.HAVE_ARGUMENT:
                    i += 2
        except:
            # well, it was worth a try; default to be lib
            return
    else:
        # we were imported from a file; let's go there and see how
        import linecache
        linecache.checkcache(filename)
        line = linecache.getline(filename,
                                 frame.f_lineno,
                                 frame.f_globals)
        line = line.split()
        try:
            i = line.index('import')
            if i >= 2 and line[i - 2] == 'from':
                mod = line[i - 1]
                what = line[i + 1]
            else:
                mod = line[i + 1]
                what = None
            if mod == __name__:
                libmode = what == 'lib'
        except:
            # my code parsing fu is not strong enough
            return

closure()
del closure

if not libmode:
    # ok, so we are not in lib-mode; add non-lib functionality
    from nonlib import *
    # promote all names in pwn.lib
    from lib import *
