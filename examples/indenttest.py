import pwn

pwn.context.log_level = 'info'

# print pwn2.lib
pwn.log.info(('A' * 100 + '\n') * 4)

raw_input('>')
