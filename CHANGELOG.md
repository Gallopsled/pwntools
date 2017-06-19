# Changelog

This changelog only includes added major features and changes. Bugfixes and
minor changes are omitted.

## Release History

The table below shows which release corresponds to each branch, and what date the version was released.

| Version          | Branch   | Release Date           |
| ---------------- | -------- | ---------------------- |
| [3.9.0](#390)    | `dev`    | Sep 8, 2017 (planned)
| [3.8.0](#380)    | `beta`   | Jul 28, 2017 (planned)
| [3.7.0](#370)    | `stable` | Jun 19, 2017
| [3.6.1](#361)    |          | May 12, 2017
| [3.6.0](#360)    |          | May 8, 2017
| [3.5.1](#351)    |          | Apr 15, 2017
| [3.5.0](#350)    |          | Mar 26, 2017
| [3.4.1](#341)    |          | Feb 17, 2017
| [3.4.0](#340)    |          | Feb 13, 2017
| [3.3.4](#334)    |          | Jan 12, 2016
| [3.3.3](#333)    |          | Jan 10, 2016
| [3.3.2](#332)    |          | Jan 10, 2016
| [3.3.1](#331)    |          | Jan 10, 2016
| [3.3.0](#330)    |          | Dec 24, 2016
| [3.2.1](#321)    |          | Dec 24, 2016
| [3.2.0](#320)    |          | Nov 12, 2016
| [3.1.1](#311)    |          | Oct 23, 2016
| [3.1.0](#310)    |          | Oct 2, 2016
| [3.0.4](#304)    |          | Sept 19, 2016
| [3.0.3](#303)    |          | Sept 18, 2016
| [3.0.2](#302)    |          | Sept 6, 2016
| [3.0.1](#301)    |          | Aug 20, 2016
| [3.0.0](#300)    |          | Aug 20, 2016
| [2.2.0](#220)    |          | Jan 5, 2015

## 3.9.0

To be released on Sep 8, 2017.

## 3.8.0

To be released on Jul 28, 2017.

- [#981][981] Fixed RELRO detection logic
- [#986][986] Enhancements to DynELF for controlling usage of LibcDB

[981]: https://github.com/Gallopsled/pwntools/issues/981
[986]: https://github.com/Gallopsled/pwntools/issues/986

## 3.7.0

- [#933][933] DynELF works better with different base addresses
- [#952][952] A few small fixes were made to `pwn template`, and the CRC database was updated.
- [5c72d62c][5c72d62c] Updated the CRC database

[933]: https://github.com/Gallopsled/pwntools/issues/933
[952]: https://github.com/Gallopsled/pwntools/issues/952
[5c72d62c]: https://github.com/Gallopsled/pwntools/commit/5c72d62c

## 3.6.1

- [#979][979]+[1a4a1e1][1a4a1e1] Fixed [#974][974], a bug related to the terminal handling and numlock.
- [#980][980] Fixed the `pwn template` command.

[974]: https://github.com/Gallopsled/pwntools/issues/974
[979]: https://github.com/Gallopsled/pwntools/pull/979
[980]: https://github.com/Gallopsled/pwntools/pull/980
[1a4a1e1]: https://github.com/Gallopsled/pwntools/commit/1a4a1e1

## 3.6.0

- [#895][895] Added a Dockerfile to simplify testing setup and allow testing on OSX
- [#897][897] Fixed some incorrect AArch64 syscals
- [#893][893] Added the `pwnlib.config` module
    + Configuration options can now be set in `~/.pwn.conf`
    + This replaces the old, **undocumented** mechanism for changing logging colors.  Only @br0ns and @ebeip90 were likely using this.
    + More information is available in the documentation [here](http://docs.pwntools.com/en/dev/config.html).
- [#899][899] Pwntools now uses Unicorn Engine to emulate PLT instructions to ensure correct mapping of PIE / RELRO binaries.
- [#904][904] Enhancements to the accuracy of the `pwn checksec` command.
- [#905][905] Added a `pwn debug` command-line utility which automates the process of `gdb.attach(process(...))` to spawn GDB
    + More information is available in the documentation [here](http://docs.pwntools.com/en/dev/commandline.html#pwn-debug)
- [#919][919] Added a `pwn template` command-line utility to simplify the process of bootstrapping a new exploit.
    + More information is available in the documentation [here](http://docs.pwntools.com/en/dev/commandline.html#pwn-template).
- [#948][948] Fix unnecessary warning for Core files
- [#954][954] Fix list processing in `~/.pwn.conf`
- [#967][967] Respect `TERM_PROGRAM` for `run_in_new_terminal`
- [#970][970] Fix overly-aggressive corefile caching

[947]: https://github.com/Gallopsled/pwntools/pull/947
[948]: https://github.com/Gallopsled/pwntools/pull/948
[954]: https://github.com/Gallopsled/pwntools/pull/954
[960]: https://github.com/Gallopsled/pwntools/pull/960
[967]: https://github.com/Gallopsled/pwntools/pull/967
[968]: https://github.com/Gallopsled/pwntools/pull/968
[970]: https://github.com/Gallopsled/pwntools/pull/970

[895]: https://github.com/Gallopsled/pwntools/pull/895
[897]: https://github.com/Gallopsled/pwntools/pull/897
[893]: https://github.com/Gallopsled/pwntools/pull/893
[899]: https://github.com/Gallopsled/pwntools/pull/899
[904]: https://github.com/Gallopsled/pwntools/pull/904
[905]: https://github.com/Gallopsled/pwntools/pull/905
[919]: https://github.com/Gallopsled/pwntools/pull/919

## 3.5.1

- [#945][945] Speed up ssh via caching checksec results (fixes [#944][944])
- [#950][950] Fixes a bug where setting `context.arch` does not have an effect on `adb.compile()` output architecture

[944]: https://github.com/Gallopsled/pwntools/issues/944
[945]: https://github.com/Gallopsled/pwntools/pull/945
[950]: https://github.com/Gallopsled/pwntools/pull/950

## 3.5.0

- [b584ca3][b584ca3] Fixed an issue running `setup.py` on ARM
- [#822][822] Enabled relative leaks with `MemLeak`
    + This should be useful for e.g. heap-relative leaks
- [#832][832] Changed all internal imports to use absolute imports (no functional changes)
- [a12d0b6][a12d0b6] Move `STDOUT`, `PIPE`, `PTY` constants to globals
    + `process(..., stdin=process.PTY)` --> `process(..., stdin=PTY)`
- [#828][828] Use `PR_SET_PTRACER` for all `process()` and `ssh.process()` instances
    + This simplifies debugging on systems with YAMA ptrace enabled
- Various documentation enhancements
    + In particular, the [gdb][gdb], [elf][elf], and [ssh][ssh] docs are much better
- [#833][833] Performance enhancements for `adb` module
- [d0267f3][d0267f3] `packing.fit()` now treats large offsets as cyclic patterns (e.g. `0x61616161` behaves the same as `"aaaa"`)
- [#835][835] Added `ssh.checksec`
    + Reports the kernel version and other relevant information on connection
- [#857][857] Slightly shortened `execve` shellcode
- [300f8e0][300f8e0] Slightly speed up processing of large ELF files
- [#861][861] Adds support for extracting `IKCONFIG` configs from Linux kernel images, and extends `checksec` to report on any insecure configurations discovered
- [#871][871] Moves all of the basic syscall templates to `shellcraft/common` and exposes them via symlinks.  Closed [#685][685]
    + Should not have any visible effects from any documented APIs
    + `shellcraft.arch.os.syscall_function()` still works the same
    + We now have the ability to differentiate between the `connect` syscall, and a TCP `connect` helper
- [#887][887] `sh_string` now returns a quoted empty string `''` rather than just an empty string
- [#839][839] Exposes a huge amount of functionality via corefiles which was not previously availble.  See the [docs][corefile_docs] for examples.
    + `process().corefile` will automatically instantiate a Corefile for the process
    + QEMU-emulated processes are supported
    + Native processes are supported, including extraction of coredumps from `apport` crash logs
    + Native processes can be dumped *while running*, in a manner similar to `GDB`'s `gcore` script
- [#875][857] Added [documentation][aarch64] (and tests) for AArch64 shellcode
- [#882][882] The `ROP` class now respects `context.bytes` instead of using the hard-coded value of `4` (fixed [#879][879])
- [#869][869] Added several fields to the `process` class (`uid`, `gid`, `suid`, `sgid`) which are recorded at execution time, based on the file permissions
- [#868][868] Changed the way that `ssh.process()` works internally, and it now returns a more specialized class, `ssh_process`.
    + Added `ssh_process.corefile` for fetching remote corefiles
    + Added `ssh_process.ELF` for getting an ELF of the remote executable
    + The `uid`, `gid`, and `suid`, and `sgid` which are recorded at execution time, based on the file permissions
- [#865][865] Fixes `ELF.read` to support contiguous memory reads across non-contiguous file-backed segments
- [#862][862] Adds a `symlink=` argument to `ssh.set_working_directory`, which will automatically symlink all of the files in the "old" working directory into the "new" working directory

[ssh]: http://docs.pwntools.com/en/dev/tubes/ssh.html
[gdb]: http://docs.pwntools.com/en/dev/gdb.html
[elf]: http://docs.pwntools.com/en/dev/elf.html
[corefile_docs]: http://docs.pwntools.com/en/dev/elf/corefile.html
[aarch64]: http://docs.pwntools.com/en/dev/shellcraft/aarch64.html

[685]: https://github.com/Gallopsled/pwntools/pull/685
[822]: https://github.com/Gallopsled/pwntools/pull/822
[828]: https://github.com/Gallopsled/pwntools/pull/828
[832]: https://github.com/Gallopsled/pwntools/pull/832
[833]: https://github.com/Gallopsled/pwntools/pull/833
[835]: https://github.com/Gallopsled/pwntools/pull/835
[839]: https://github.com/Gallopsled/pwntools/pull/839
[857]: https://github.com/Gallopsled/pwntools/pull/857
[861]: https://github.com/Gallopsled/pwntools/pull/861
[862]: https://github.com/Gallopsled/pwntools/pull/862
[865]: https://github.com/Gallopsled/pwntools/pull/865
[868]: https://github.com/Gallopsled/pwntools/pull/868
[869]: https://github.com/Gallopsled/pwntools/pull/869
[871]: https://github.com/Gallopsled/pwntools/pull/871
[875]: https://github.com/Gallopsled/pwntools/pull/857
[879]: https://github.com/Gallopsled/pwntools/issues/879
[882]: https://github.com/Gallopsled/pwntools/pull/882
[887]: https://github.com/Gallopsled/pwntools/pull/887


[b584ca3]: https://github.com/Gallopsled/pwntools/commit/b584ca3
[a12d0b6]: https://github.com/Gallopsled/pwntools/commit/a12d0b6
[d0267f3]: https://github.com/Gallopsled/pwntools/commit/d0267f3
[300f8e0]: https://github.com/Gallopsled/pwntools/commit/300f8e0

## 3.4.1

- [#894][894] Fix a bug when using `gdb.debug()` over ssh.
- [e021f57][e021f57] Fix a bug ([#891][891]) in `rop` when needing to insert padding to fix alignment

[e021f57]: https://github.com/Gallopsled/pwntools/commit/e021f57
[894]: https://github.com/Gallopsled/pwntools/pull/894
[891]: https://github.com/Gallopsled/pwntools/issues/891

## 3.4.0

- [#800][800] Add `shell=` option to `ssh.process()`
- [#806][806] Add `context.buffer_size` for fine-tuning `tube` performance
    + Also adds `buffer_fill_size=` argument for all tubes
- [b83a6c7][b83a6c7] Fix undocumented `process.leak` function
- [546061e][546061e] Modify `coredump_filter` of all spawned processes, so that core dumps are more complete
- [#809][809] Add several functions to `adb` (`unlink`, `mkdir`, `makedirs`, `isdir`, `exists`)
- [#817][817] Make disconnection detection more robust

[800]: https://github.com/Gallopsled/pwntools/pull/800
[806]: https://github.com/Gallopsled/pwntools/pull/806
[809]: https://github.com/Gallopsled/pwntools/pull/809
[817]: https://github.com/Gallopsled/pwntools/pull/817
[5d9792f]: https://github.com/Gallopsled/pwntools/commit/5d9792f
[b83a6c7]: https://github.com/Gallopsled/pwntools/commit/b83a6c7
[546061e]: https://github.com/Gallopsled/pwntools/commit/546061e

## 3.3.4

- [#850][850] and [#846][846] fix issues with `hexdump` and the `phd` command-line utility, when using pipes (e.g. `echo foo | phd`)
- [#852][852] Fixes register ordering in `regsort`
- [#853][853] Fixes the registers restored in `shellcraft.amd64.popad`

[846]: https://github.com/gallopsled/pwntools/pull/846
[850]: https://github.com/gallopsled/pwntools/pull/850
[852]: https://github.com/gallopsled/pwntools/pull/852
[853]: https://github.com/gallopsled/pwntools/pull/853

## 3.3.3

- [#843][843] fixed a bug in `amd64.mov`.

[843]: https://github.com/gallopsled/pwntools/pull/843

## 3.3.2

- [#840][840] fixed a regression introduced by [#837][837].

[840]: https://github.com/gallopsled/pwntools/pull/840

## 3.3.1

- [#833][833] Fixed a performance-impacting bug in the adb module.
- [#837][837] Fixed a bug([#836][836]) causing `hexdump(cyclic=True)` to throw an exception.

[833]: https://github.com/Gallopsled/pwntools/pull/833
[837]: https://github.com/Gallopsled/pwntools/pull/837
[836]: https://github.com/Gallopsled/pwntools/issues/836

## 3.3.0

- [b198ec8][b198ec8] Added `tube.stream()` function, which is like `tube.interact()` without a prompt or keyboard input.
    + Effectively, this is similar to `cat file` and just prints data as fast as it is received.
- [aec3fa6][aec3fa6] Disable update checks against GitHub
    + These checks frequently broke due to GitHub query limits
- [#757][757] Fixed `adb.wait_for_device()` re-use of the same connection
- [f9133b1][f9133b1] Add a `STDERR` magic argument to make logging go to `stderr` instead of `stdout`
    + Usage is e.g. `python foo.py STDERR` or `PWNLIB_STDERR=1 python foo.py`
    + Also adds `context.log_console` to log to any file or terminal
- [67e11a9][67e11a9] Add faster error checking to `cyclic()` when provided very large values
- [5fda658][5fda658] Expose BitPolynom in `globals()`
- [#765][765] Added `-d` option for hex-escaped output for `shellcraft` command-line tool
- [#772][772] Fixed bash completion regressions
- [30c34b7][30c34b7] Fix `ROP.call()` with `Function` objects from `ELF.functions`
- [fa402ce][fa402ce] Add `adb.uptime` and `adb.boot_time`
- [82312ba][82312ba] Add `cyclic_metasploit` and `cyclic_metasploit_find`

[757]: https://github.com/Gallopsled/pwntools/pull/757
[765]: https://github.com/Gallopsled/pwntools/pull/765
[772]: https://github.com/Gallopsled/pwntools/pull/772
[b198ec8]: https://github.com/Gallopsled/pwntools/commit/b198ec8
[aec3fa6]: https://github.com/Gallopsled/pwntools/commit/aec3fa6
[f9133b1]: https://github.com/Gallopsled/pwntools/commit/f9133b1
[67e11a9]: https://github.com/Gallopsled/pwntools/commit/67e11a9
[5fda658]: https://github.com/Gallopsled/pwntools/commit/5fda658
[30c34b7]: https://github.com/Gallopsled/pwntools/commit/30c34b7
[fa402ce]: https://github.com/Gallopsled/pwntools/commit/fa402ce
[82312ba]: https://github.com/Gallopsled/pwntools/commit/82312ba

## 3.2.1

Multiple bug fixes.

- [#783][783] Fix `adb.uninstall` typo
- [#787][787] Added error handling for `ssh.process` argument `preexec_fn`
- [#793][793] Fixed progress message in `remote()` when connections failed
- [#802][802] Fixed partition listing in `adb.partitions`, which accidentally shelled out to the `adb` binary
- [#804][804] Fix error message for 32-bit distributions
- [#805][805] Fix exception in `Core.segments` when a segment has no name
- [#811][811] Fixes and performance improvements for `adb.wait_for_device()`
- [#813][813] Fixed a release script
- [#814][814] Fixed exceptions thrown if the `$HOME` directory is not writable
- [#815][815] Properly handle `None` in `MemLeak`

[783]: https://github.com/Gallopsled/pwntools/pull/783
[787]: https://github.com/Gallopsled/pwntools/pull/787
[793]: https://github.com/Gallopsled/pwntools/pull/793
[802]: https://github.com/Gallopsled/pwntools/pull/802
[804]: https://github.com/Gallopsled/pwntools/pull/804
[805]: https://github.com/Gallopsled/pwntools/pull/805
[811]: https://github.com/Gallopsled/pwntools/pull/811
[813]: https://github.com/Gallopsled/pwntools/pull/813
[814]: https://github.com/Gallopsled/pwntools/pull/814
[815]: https://github.com/Gallopsled/pwntools/pull/815

## 3.2.0

- [#695][695] Fixed a performance regression in `phd`.
- [452605e][452605e] Fixed [#629][629] related to correct removal of temporary files.
- [ea94ee4][ea94ee4] Disallows semi-colons in for the `run_in_terminal` function, since it did not work properly in all cases.
- [6376d07][6376d07] Added the mips shellcode `pushstr_array`.
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
- [#703][703] Added new methods to `adb`
    + `install` - Installs an APK
    + `uninstall` - Uninstalls a package
    + `packages` - Lists installed packages
- [4893819][4893819] Modified `shellcraft.sh` on all platforms to provide `argv[0]` and set `argc==1`
    + This is needed for systems which have Busybox or other minimal shell for `/bin/sh` which does not behave well with `argc==0` or `argv[0]==NULL`.
- [1e414af][1e414af] Added `connect()` alias for `remote()`
    + For example, `io=connect('google.com', 80)`
    + This also works with `tcp(...)` and `udp(...)` aliases
- [869ec42][869ec42] Added `ssh.read()` and `ssh.write()` aliases
- [2af55c9][2af55c9] `AdbDevice` objects exposed via e.g. `adb.devices()` now offer scoped access to all `adb` module properties
    + It is now possible to e.g. `map(lambda d: d.process(['id']).recvall(), adb.devices())`


[629]: https://github.com/Gallopsled/pwntools/issues/629
[695]: https://github.com/Gallopsled/pwntools/pull/695
[700]: https://github.com/Gallopsled/pwntools/pull/700
[701]: https://github.com/Gallopsled/pwntools/pull/701
[704]: https://github.com/Gallopsled/pwntools/pull/704
[711]: https://github.com/Gallopsled/pwntools/pull/711
[717]: https://github.com/Gallopsled/pwntools/pull/717
[709]: https://github.com/Gallopsled/pwntools/pull/709
[705]: https://github.com/Gallopsled/pwntools/pull/705
[703]: https://github.com/Gallopsled/pwntools/pull/703
[452605e]: https://github.com/Gallopsled/pwntools/commit/452605e854f4870ef5ccfdf7fb110dfd75c50feb
[ea94ee4]: https://github.com/Gallopsled/pwntools/commit/ea94ee4ca5a8060567cc9bd0dc33796a89ad0b95
[6376d07]: https://github.com/Gallopsled/pwntools/commit/6376d072660fb2250f48bd22629bbd7e3c61c758
[1e414af]: https://github.com/Gallopsled/pwntools/commit/1e414afbeb3a01242f4918f111febaa63b640eb7
[869ec42]: https://github.com/Gallopsled/pwntools/commit/869ec42082b4b98958dfe85103da9b101dde7daa
[4893819]: https://github.com/Gallopsled/pwntools/commit/4893819b4c23182da570e2f4ea4c14d73af2c0df
[2af55c9]: https://github.com/Gallopsled/pwntools/commit/2af55c9bc382eca23f89bc0abc7a07c075521f94

## 3.1.1

Fixed a bug in `MemLeak.struct` (PR: #768).

## 3.1.0

A number of smaller bugfixes and documentation tweaks.

## 3.0.4

- Fixed a bug that made 3.0.3 uninstallable (Issue: #751, PR: #752)

## 3.0.3

- Fixed some performance and usability problems with the update system (Issues:
  #723, #724, #736. PRs: #729, #738, #747).
- Fixed a bug related to internals in pyelftools (PRs: #730, #746).
- Fixed an issue with travis (Issue: #741, PRs: #743, #744, #745).

## 3.0.2

- Cherry-pick #695, as this was a regression-fix.
- Added a fix for the update checker, as it would suggest prereleases as updates to stable releases.
- Various documentation fixes.

## 3.0.1

A small bugfix release. There were a lot of references to the `master`-branch, however after 3.0.0 we use the names `stable`, `beta` and `dev` for our branches.

## 3.0.0

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
- Added `context.randomize` to control randomization of settings like XOR keys and register ordering (default off).
- Added `context.terminal` for setting how to launch commands in a new terminal.

#### DynELF and MemLeak Module

- Added a `DynELF().libc` property which attempt to find the remote libc and download the ELF from LibcDB.
- Added a `DynELF().stack` property which leaks the `__environ` pointer from libc, making it easy to leak stack addresses.
- Added `MemLeak.String` and `MemLeak.NoNewlines` and other related helpers for handling special leakers which cannot e.g. handle newlines in the leaked addresses and which leak a C string (e.g. auto-append a `'\x00'`).
- Enhancements for leaking speed via `MemLeak.compare` to avoid leaking an entire field if we can tell from a partial leak that it does not match what we are searching for.

#### Encoders Module

- Added a `pwnlib.encoders` module for assembled-shellcode encoders/decoders
- Includes position-independent basic XOR encoders
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

## 2.2.0

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
