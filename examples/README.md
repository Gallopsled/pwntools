# Examples
While these examples should all work, they are not very representative of
the pwntools project.

We have a plan to create a separate repository with examples, primarily
exploits. Until we do so, we recommend new users to look at
https://docs.pwntools.com, as this is a better overview of our features.

In no particular order the docstrings for each example:

* `args.py`
```
When not in lib-mode (import `pwn` rather than `pwnlib`) we parse the
commandline for variables definitions.  A variable definition has the form::

  <var>=<val>

where ``<var>`` contains only uppercase letters, digits and underscores and
doesn't start with a digit.

Try running this example with::

  $ python args.py RHOST=localhost RPORT=1337
```
* `asm.py`
```
Example showing the interface to `pwnlib.asm.asm` and `pwnlib.shellcraft`.
```
* `attach.py`
```
Example showing `pwnlib.gdb.attach()`
```
* `clean_and_log.py`
```
Use case for `pwnlib.tubes.tube.clean_and_log`.

Sometimes you will have a solution to a challenge but you don't know what it
will look like when you get the flag.  Sometimes that will leave you with a
top-level exception, no flag, and angry team members.

Solution:
 1. Always run wireshark or tcpdump.  Always.
 2. Register <your socket>.clean or <your socket>.clean_and_log to run at exit.
```
* `indented.py`
```
When running in term-mode (import `pwn` rather than `pwnlib`, stdout is a TTY
and not running in a REPL), we can do proper indentation where lines too long to
fit on a screen are split into multiple individually indented lines.

Too see the difference try running with::

  $ python indented.py

and

  $ python -i indented.py

Also notice that `pause()` can react on any key when in `term_mode`.
```
* `listen_uroboros.py`
```
An example showing interconnection of sockets.  This script will wait for three
connections on port 1337, then connect them like a three-way Uroboros.
```
* `options.py`
```
Example showing `pwnlib.ui.options()`
```
* `port_forward.py`
```
A very simple port forwarder using `pwnlib.tubes.tube.connect_both()`.
```
* `readline_completers.py`
```
Example showing pwnlib's readline implementation and a few completers.  This
part of pwnlib will probably see some major changes soon, but we wanted to show
off some proof-of-concepts.
```
* `remote.py`
```
Example showing how to use the remote class.
```
* `remote_gdb_debugging.py`
```
Simple example showing how to use the remote
gdb debugging features available in pwntools.
```
* `spinners.py`
```
Just a lot of spinners!
```
* `splash.py`
```
"Easteregg"
```
* `ssh.py`
```
Example showing how to use the ssh class.
```
* `text.py`
```
Example showing how to use `pwnlib.term.text`.

Try running with::

  $ TERM=xterm python text.py

and::

  $ TERM=xterm-256color python text.py
```
* `yesno.py`
```
Example showing `pwnlib.ui.yesno()`
```
