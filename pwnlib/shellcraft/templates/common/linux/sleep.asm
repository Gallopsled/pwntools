<%
  import pwnlib.abi
  from pwnlib import shellcraft
%>
<%page args="seconds"/>
<%docstring>
Sleeps for the specified amount of seconds.

Uses SYS_nanosleep under the hood.
Doesn't check for interrupts and doesn't retry with the remaining time.

Args:
  seconds (int,float): The time to sleep in seconds.
</%docstring>
<%
  # struct timespec {
  #     time_t  tv_sec;  /* Seconds */
  #     long    tv_nsec; /* Nanoseconds */
  # };
  tv_sec = int(seconds)
  tv_nsec = int((seconds % 1) * 1000000000)

  abi = pwnlib.abi.ABI.syscall()
  stack = abi.stack
%>
    /* sleep(${seconds}) */
    ${shellcraft.push(tv_nsec)}
    ${shellcraft.push(tv_sec)}
    ${shellcraft.nanosleep(stack, 0)}
