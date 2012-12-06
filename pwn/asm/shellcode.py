shellcodes = []

def register_shellcode(func, context):
    shellcodes.append((func, func.func_name, context))
