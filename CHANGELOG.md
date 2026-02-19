# Changelog

This changelog only includes added major features and changes. Bugfixes and
minor changes are omitted.

## Release History

The table below shows which release corresponds to each branch, and what date the version was released.

| Version          | Branch   | Release Date           |
| ---------------- | -------- | ---------------------- |
| [5.0.0](#500-dev)  | `dev`    |
| [4.15.0](#4150-stable)  | `stable` | Oct 12, 2025
| [4.14.1](#4141)  |          | Mar 24, 2025
| [4.14.0](#4140)  |          | Jan 15, 2025
| [4.13.1](#4131)  |          | Sep 29, 2024
| [4.13.0](#4130)  |          | Aug 12, 2024
| [4.12.0](#4120)  |          | Feb 22, 2024
| [4.11.1](#4111)  |          | Nov 14, 2023
| [4.11.0](#4110)  |          | Sep 15, 2023
| [4.10.0](#4100)  |          | May 21, 2023
| [4.9.0](#490)    |          | Dec 29, 2022
| [4.8.0](#480)    |          | Apr 21, 2022
| [4.7.1](#471)    |          | Apr 20, 2022
| [4.7.0](#470)    |          | Nov 15, 2021
| [4.6.0](#460)    |          | Jul 12, 2021
| [4.5.1](#451)    |          | May 30, 2021
| [4.5.0](#450)    |          | Apr 30, 2021
| [4.4.0](#440)    |          | Mar 29, 2021
| [4.3.1](#431)    |          | Nov 29, 2020
| [4.3.0](#430)    |          | Oct 20, 2020
| [4.2.0](#420)    |          | Jul 3, 2020
| [4.1.7](#417)    |          | Jun 30, 2020
| [4.1.5](#415)    |          | Jun 27, 2020
| [4.1.4](#414)    |          | Jun 26, 2020
| [4.1.3](#413)    |          | Jun 23, 2020
| [4.1.2](#412)    |          | Jun 5, 2020
| [4.1.1](#411)    |          | Jun 3, 2020
| [4.1.0](#410)    |          | May 8, 2020
| [4.0.1](#401)    |          | Jan 22, 2020
| [4.0.0](#400)    |          | Jan 09, 2020
| [3.13.0](#3130)  |          | Nov 5, 2019
| [3.12.2](#3122)  |          | Jan 8, 2019
| [3.12.1](#3121)  |          | Sept 17, 2018
| [3.12.0](#3120)  |          | Feb 22, 2018
| [3.11.0](#3110)  |          | Jan 3, 2018
| [3.10.0](#3100)  |          | Oct 25, 2017
| [3.9.2](#392)    |          | Oct 5, 2017
| [3.9.1](#391)    |          | Sep 28, 2017
| [3.9.0](#390)    |          | Sep 11, 2017
| [3.8.0](#380)    |          | Jul 29, 2017
| [3.7.1](#371)    |          | Jul 14, 2017
| [3.7.0](#370)    |          | Jun 19, 2017
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

## 5.0.0 (`dev`)

- [#2677][2677] refactor: replace unsafe eval with ast.literal_eval in ROP cache loading
- [#2675][2675] feat(term): add zellij support
- [#2652][2652] Make setting the context.terminal to kitty more user friendly
- [#2638][2638] feat: add disable_corefiles context option
- [#2627][2627] remove pwnlib.util.iters.lookahead (broken anyway)
- [#2598][2598] aarch64: Fix ABI definition
- [#2419][2419] riscv: avoid compressed instructions (if you need compressed, use .option rvc)
- [#2551][2551] Detect when kitty is being used as terminal
- [#2519][2519] Drop Python 2.7 support / Require Python 3.10
- [#2507][2507] Add `+LINUX` and `+WINDOWS` doctest options and start proper testing on Windows
- [#2522][2522] Support starting a kitty debugging window with the 'kitten' command
- [#2524][2524] Raise EOFError during `process.recv` when stdout closes on Windows
- [#2526][2526] Properly make use of extra arguments in `packing` utilities. `sign` parameter requires keyword syntax to specify it.
- [#2517][2517] Allow to passthru kwargs on `ssh.__getattr__` convenience function to fix SSH motd problems
- [#2530][2530] Do NOT error when passing directory arguments in `checksec` commandline tool.
- [#2529][2529] Add LoongArch64 support
- [#2506][2506] ROP: fix `ROP(ELF(exe)).leave` is `None` in some ELF
- [#2504][2504] doc: add example case for `tuple` (host, port pair) in `gdb.attach`
- [#2546][2546] ssh: Allow passing disabled_algorithms keyword argument from ssh to paramiko
- [#2538][2538] Add `ssh -L` / `ssh.connect_remote()` workaround when `AllowTcpForwarding` is disabled
- [#2574][2574] Allow creating an ELF from in-memory bytes
- [#2575][2575] Detect when Terminator is being used as terminal
- [#2578][2578] Add gnome-terminal, Alacritty, Ttilix for run_in_new_terminal
- [#2590][2590] Add support for finding corefiles under WSL2
- [#2496][2496] Add linux ko file search support
- [#2542][2542] Decode `_IO_*` flags in `FileStructure` member
- [#2592][2592] pwnlib.config: Fix customization of `context.timeout`
- [#2608][2608] Abort on `libcdb file libc.so --unstrip` if eu-unstrip is not installed
- [#2611][2611] Cleanup `pwnlib.lexer` exports and imports
- [#2610][2610] Fix `log.progress` ignoring `context.log_console`
- [#2615][2615] tube/process: Fix redirecting stderr to stdout on Windows
- [#2639][2639] ROP: Remove stdout and argv workaround in ROPgadget invocation
- [#2630][2630] support `preexec_fn` in `debug()`
- [#2641][2641] support preexec_args in process
- [#2646][2646] fix(libcdb-cli): return early if no matched libc found
- [#2629][2629] Add `terminate()` method to process class that sends SIGTERM
- [#2643][2643] Refactor getdents.py, add support for SYS_getdents64

[2677]: https://github.com/Gallopsled/pwntools/pull/2677
[2675]: https://github.com/Gallopsled/pwntools/pull/2675
[2652]: https://github.com/Gallopsled/pwntools/pull/2652
[2638]: https://github.com/Gallopsled/pwntools/pull/2638
[2627]: https://github.com/Gallopsled/pwntools/pull/2627
[2598]: https://github.com/Gallopsled/pwntools/pull/2598
[2419]: https://github.com/Gallopsled/pwntools/pull/2419
[2551]: https://github.com/Gallopsled/pwntools/pull/2551
[2519]: https://github.com/Gallopsled/pwntools/pull/2519
[2507]: https://github.com/Gallopsled/pwntools/pull/2507
[2522]: https://github.com/Gallopsled/pwntools/pull/2522
[2524]: https://github.com/Gallopsled/pwntools/pull/2524
[2526]: https://github.com/Gallopsled/pwntools/pull/2526
[2517]: https://github.com/Gallopsled/pwntools/pull/2517
[2530]: https://github.com/Gallopsled/pwntools/pull/2530
[2529]: https://github.com/Gallopsled/pwntools/pull/2529
[2506]: https://github.com/Gallopsled/pwntools/pull/2506
[2504]: https://github.com/Gallopsled/pwntools/pull/2504
[2546]: https://github.com/Gallopsled/pwntools/pull/2546
[2538]: https://github.com/Gallopsled/pwntools/pull/2538
[2574]: https://github.com/Gallopsled/pwntools/pull/2574
[2575]: https://github.com/Gallopsled/pwntools/pull/2575
[2578]: https://github.com/Gallopsled/pwntools/pull/2578
[2590]: https://github.com/Gallopsled/pwntools/pull/2590
[2496]: https://github.com/Gallopsled/pwntools/pull/2496
[2542]: https://github.com/Gallopsled/pwntools/pull/2542
[2592]: https://github.com/Gallopsled/pwntools/pull/2592
[2608]: https://github.com/Gallopsled/pwntools/pull/2608
[2611]: https://github.com/Gallopsled/pwntools/pull/2611
[2610]: https://github.com/Gallopsled/pwntools/pull/2610
[2615]: https://github.com/Gallopsled/pwntools/pull/2615
[2639]: https://github.com/Gallopsled/pwntools/pull/2639
[2630]: https://github.com/Gallopsled/pwntools/pull/2630
[2641]: https://github.com/Gallopsled/pwntools/pull/2641
[2646]: https://github.com/Gallopsled/pwntools/pull/2646
[2629]: https://github.com/Gallopsled/pwntools/pull/2629
[2638]: https://github.com/Gallopsled/pwntools/pull/2643

## 4.15.0 (`stable`)
... (the rest of the file)