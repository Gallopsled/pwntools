import pwn2

print pwn2.lib.context
print pwn2.lib.context.dict()

pwn2.lib.context.arch = 'yolo'
