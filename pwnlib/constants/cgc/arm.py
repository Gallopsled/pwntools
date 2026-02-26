from pwnlib.constants.constant import Constant

terminate = Constant('terminate', 1)
SYS_terminate = Constant('SYS_terminate', 1)
__NR_terminate = Constant('__NR_terminate', 1)

transmit = Constant('transmit', 2)
SYS_transmit = Constant('SYS_transmit', 2)
__NR_transmit = Constant('__NR_transmit', 2)

receive = Constant('receive', 3)
SYS_receive = Constant('SYS_receive', 3)
__NR_receive = Constant('__NR_receive', 3)

fdwait = Constant('fdwait', 4)
SYS_fdwait = Constant('SYS_fdwait', 4)
__NR_fdwait = Constant('__NR_fdwait', 4)

allocate = Constant('allocate', 5)
SYS_allocate = Constant('SYS_allocate', 5)
__NR_allocate = Constant('__NR_allocate', 5)

deallocate = Constant('deallocate', 6)
SYS_deallocate = Constant('SYS_deallocate', 6)
__NR_deallocate = Constant('__NR_deallocate', 6)

random = Constant('random', 7)
SYS_random = Constant('SYS_random', 7)
__NR_random = Constant('__NR_random', 7)
