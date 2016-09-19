# Changelog

This changelog only includes added major features and changes. Bugfixes and
minor changes are omitted.

## 3.2.0 Dev (November 12, 2016)

**Currently on the _dev_ branch**

- [#695][695] Fixed a performance regression in `phd`.
- [#700][700] Added missing MIPS shellcode documentation to readthedocs, and enabled unit tests
- [#701][701] Command line tools refactored to have a common `pwn` entry point.
    + Added an option to *not* install the traditional `asm`, `disasm`, `checksec`, etc scripts
    + All existing tools can be accessed from the `pwn` command (e.g. `pwn asm nop`).
- [#704][704] The `process` object has a new, optional argument `alarm` for setting a `SIGALRM` timeout for processes.
- [#705][705] Added the Android Emulator to the test suite and Travis CI.
    + Android Emulator is now required for the full test suite
    + Android Emulator tests are skipped if no Android-related changes are detected
- [#711][711] `DynELF` has a new attribute, `heap`, which leaks the current `brk` address (heap base).  This is useful for finding heap allocations with dlmalloc-derived allocators like those used by Glibc.
- [#717][717] `sh_string` was rewritten to emit more compact and compatible strings
    + This was achieved by embedding single-quoted non-printable literals
    + Much more testing was added
    + Emitted strings are no longer copy-paste compatible, but work fine with e.g. `tubes` module and the default `subprocess` module
- [#709][709] The `adb` module now directly talks to the `adb` server process via a new module, `adb.protocol`
    + Removes the need to shell out to `adb`
    + Avoids version-compatibility issues with `adb` server vs. client

[695]: https://github.com/Gallopsled/pwntools/pull/695
[700]: https://github.com/Gallopsled/pwntools/pull/700
[701]: https://github.com/Gallopsled/pwntools/pull/701
[704]: https://github.com/Gallopsled/pwntools/pull/704
[711]: https://github.com/Gallopsled/pwntools/pull/711
[717]: https://github.com/Gallopsled/pwntools/pull/717
[709]: https://github.com/Gallopsled/pwntools/pull/709
[705]: https://github.com/Gallopsled/pwntools/pull/705

## 3.1.0 (October 1, 2016)

**Currently on the _beta_ branch**

A number of smaller bugfixes and documentation tweaks.

## 3.0.3 (September 18, 2016)

**Current release**

- Fixed some performance and usability problems with the update system (Issues:
  #723, #724, #736. PRs: #729, #738, #747).
- Fixed a bug related to internals in pyelftools (PRs: #730, #746).
- Fixed an issue with travis (Issue: #741, PRs: #743, #744, #745).

## 3.0.2 (September 6, 2016)

- Cherry-pick #695, as this was a regression-fix.
- Added a fix for the update checker, as it would suggest prereleases as updates to stable releases.
- Various documentation fixes.

## 3.0.1 (August 20, 2016)

A small bugfix release. There were a lot of references to the `master`-branch, however after 3.0.0 we use the names `stable`, `beta` and `dev` for our branches.

## 3.0.0 (August 20, 2016)

This was a large release (1305 commits since 2.2.0) with a lot of bugfixes and changes.  The Binjitsu project, a fork of Pwntools, was merged back into Pwntools.  As such, its features are now available here.

As always, the best source of information on specific features is the comprehensive docs at https://pwntools.readthedocs.org.

This list of changes is non-complete, but covers all of the significant changes which were appropriately documented.

#### Android

Android support via a new `adb` module, `context.device`, `context.adb_host`, and `context.adb_port`.

#### Assembly and Shellcode

- Assembly module enhancements for making ELF modules from assembly or pre-assembled shellcode.  See `asm.make_elf` and `asm.make_elf_from_assembly`.
- `asm` and `shellcraft` command-line tools support flags for the new shellcode encoders
- `asm` and `shellcraft` command-line tools support `--debug` flag for automatically launching GDB on the result
- Added MIPS, PowerPC, and AArch64 support to the `shellcraft` module
- Added Cyber Grand Challenge (CGC) support to the `shellcraft` module
- Added syscall wrappers for every Linux syscall for all supported architectures to the `shellcraft` module
    + e.g. `shellcraft.<arch>.gettimeofday`
- (e.g. `shellcraft.i386.linux.`)
- Added in-memory ELF loaders for most supported architectures
    + Only supports statically-linked binaries
    + `shellcraft.<arch>.linux.loader`

#### Context Module

- Added `context.aslr` which controls ASLR on launched processes.  This works with both `process()` and `ssh.process()`, and can be specified per-process with the `aslr=` keyword argument.
- Added `context.binary` which automatically sets all `context` variables from an ELF file.
- Added `context.device`, `context.adb`, `context.adb_port`, and `context.adb_host` for connecting to Android devices.
- Added `context.kernel` setting for SigReturn-Oriented-Programming (SROP).
- Added `context.log_file` setting for sending logs to a file.  This can be set with the `LOG_FILE` magic command-line option.
- Added `context.noptrace` setting for disabling actions which require `ptrace` support.  This is useful for turning all `gdb.debug` and `gdb.attach` options into no-ops, and can be set via the `NOPTRACE` magic command-line option.
- Added `context.proxy` which hooks all connections and sends them to a SOCKS4/SOCKS5.  This can be set via the `PROXY` magic command-line option.
- Added `context.randomize` to control randommization of settings like XOR keys and register ordering (default off).
- Added `context.terminal` for setting how to launch commands in a new terminal.

#### DynELF and MemLeak Module

- Added a `DynELF().libc` property which attempt to find the remote libc and download the ELF from LibcDB.
- Added a `DynELF().stack` property which leaks the `__environ` pointer from libc, making it easy to leak stack addresses.
- Added `MemLeak.String` and `MemLeak.NoNewlines` and other related helpers for handling special leakers which cannot e.g. handle newlines in the leaked addresses and which leak a C string (e.g. auto-append a `'\x00'`).
- Enhancements for leaking speed via `MemLeak.compare` to avoid leaking an entire field if we can tell from a partial leak that it does not match what we are searching for.

#### Encoders Module

- Added a `pwnlib.encoders` module for assembled-shellcode encoders/decoders
- Includes position-indepentent basic XOR encoders
- Includes position-independent delta encoders
- Includes non-position-independent alphanumeric encoders for Intel
- Includes position-independent alphanumeric encoders for ARM/Thumb

#### ELF Module

- Added a `Core` object which can parse core-files, in order to extract / search for memory contents, and extract register states (e.g. `Core('./corefile').eax`).

#### Format Strings

- Added a basic `fmtstr` module for assisting with Format String exploitation

#### GDB Module

- Added support for debugging Android devices when `context.os=='android'`
- Added helpers for debugging shellcode snippets with `gdb.debug_assembly()` and `gdb.debug_shellcode()`

#### ROP Module

- Added support for SigReturn via `pwnlib.rop.srop`
    + Occurs automatically when syscalls are invoked and a function cannot be found
    + SigReturn frames can be constructed manually with `SigreturnFrame()` objects
- Added functional doctests for ROP and SROP

#### Tubes Process Module

- `process()` has many new options, check out the documentation
    + `aslr` controls ASLR
    + `setuid` can disable the effect of setuid, allowing core dumps (useful for extracting crash state via the new `Core()` object)
    + TTY echo and control characters can be enabled via `raw` argument
- `stdout` and `stderr` are now PTYs by default
    + `stdin` can be set to a PTY also via setting `stdin=process.PTY`

#### Tubes SSH Module

- Massive enhancements all over
- `ssh` objects now have a `ssh.process()` method which avoids the need to handle shell expansion via the old `ssh.run()` method
- Files are downloaded via SFTP if available
- New `download` and `upload` methods auto-detect whether the target is a file or directory and acts accordingly
- Added `listen()` method alias for `listen_remote()`
- Added `remote()` method alias for `connect_remote()`

#### Utilities

- Added `fit()` method to combine the functionality of `flat()` with the functionality of `cyclic()`
- Added `negative()` method to negate the value of an integer via two's complement, with respect to the current integer size (`context.bytes`).
- Added `xor_key()` method to generate an XOR key which avoids undesirable bytes over a given input.
- Added a multi-threaded `bruteforce()` implementation, `mbruteforce()`.
- Added `dealarm_shell()` helper to remove the effects of `alarm()` after you've popped a shell.

## 2.2.0 (January 5, 2015)

This was a large release with a lot of bugfixes and changes. Only the most significant
are mentioned here.

- Added shellcodes
- Added phd
- Re-added our expansion of itertools
- Added replacements for some semi-broken python standard library modules
- Re-implemented the rop module
- Added a serial tube
- Huge performance gains in the buffering for tubes
- Re-added user agents
- Begun using Travis CI with lots of test
- Removed bundled binutils in favor of documenting how to build them yourselves
- Added support for port forwarding though our SSH module
- Added dependency for capstone and ropgadget
- Added a lots of shellcodes
- Stuff we forgot
- Lots of documentation fixes
- Lots of bugfixes
