        ;; From /usr/src/linux-headers-3.5.0-27/include/linux/ptrace.h
        ;; From /usr/include/sys/ptrace.h
        %define PTRACE_TRACEME       0
        %define PTRACE_PEEKTEXT      1
        %define PTRACE_PEEKDATA      2
        %define PTRACE_PEEKUSER      3
        %define PTRACE_POKETEXT      4
        %define PTRACE_POKEDATA      5
        %define PTRACE_POKEUSER      6
        %define PTRACE_CONT          7
        %define PTRACE_KILL          8
        %define PTRACE_SINGLESTEP    9
        %define PTRACE_GETREGS      12
        %define PTRACE_SETREGS      13
        %define PTRACE_GETFPREGS    14
        %define PTRACE_SETFPREGS    15
        %define PTRACE_ATTACH       16
        %define PTRACE_DETACH       17
        %define PTRACE_GETFPXREGS   18
        %define PTRACE_SETFPXREGS   19

        %define PTRACE_SYSCALL      24

        ;; 0x4200-0x4300 are reserved for architecture-independent additions.
        ;;
        ;; Generic ptrace interface that exports the architecture specific regsets
        ;; using the corresponding NT_* types (which are also used in the core dump).
        ;; Please note that the NT_PRSTATUS note type in a core dump contains a full
        ;; 'struct elf_prstatus'. But the user_regset for NT_PRSTATUS contains just the
        ;; elf_gregset_t that is the pr_reg field of 'struct elf_prstatus'. For all the
        ;; other user_regset flavors, the user_regset layout and the ELF core dump note
        ;; payload are exactly the same layout.
        ;;
        ;; This interface usage is as follows:
        ;;  struct iovec iov = { buf, len};
        ;;
        ;;  ret = ptrace(PTRACE_GETREGSET/PTRACE_SETREGSET, pid, NT_XXX_TYPE, &iov);
        ;;
        ;; On the successful completion, iov.len will be updated by the kernel,
        ;; specifying how much the kernel has written/read to/from the user's iov.buf.
        ;;
        %define PTRACE_SETOPTIONS     0x4200
        %define PTRACE_GETEVENTMSG    0x4201
        %define PTRACE_GETSIGINFO     0x4202
        %define PTRACE_SETSIGINFO     0x4203
        %define PTRACE_GETREGSET      0x4204
        %define PTRACE_SETREGSET      0x4205
        %define PTRACE_SEIZE          0x4206
        %define PTRACE_INTERRUPT      0x4207
        %define PTRACE_LISTEN         0x4208

        ;; Flag for PTRACE_LISTEN
        %define PTRACE_SEIZE_DEVEL    0x80000000

        ;; Options set using PTRACE_SETOPTIONS
        ;; enum __ptrace_setoptions {
        %define PTRACE_O_TRACESYSGOOD     0x00000001
        %define PTRACE_O_TRACEFORK        0x00000002
        %define PTRACE_O_TRACEVFORK       0x00000004
        %define PTRACE_O_TRACECLONE       0x00000008
        %define PTRACE_O_TRACEEXEC        0x00000010
        %define PTRACE_O_TRACEVFORKDONE   0x00000020
        %define PTRACE_O_TRACEEXIT        0x00000040
        %define PTRACE_O_MASK             0x0000007f
        ;; }

        ;; Wait extended result codes for the above trace options.
        ;; enum __ptrace_eventcodes {
        %define PTRACE_EVENT_FORK       1
        %define PTRACE_EVENT_VFORK      2
        %define PTRACE_EVENT_CLONE      3
        %define PTRACE_EVENT_EXEC       4
        %define PTRACE_EVENT_VFORK_DONE 5
        %define PTRACE_EVENT_EXIT       6
        %define PTRACE_EVENT_SECCOMP    7
        ;; }
        ;; Extended result codes which enabled by means other than options.
        %define PTRACE_EVENT_STOP 128
