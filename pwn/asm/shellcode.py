all_shellcodes = []

def register_shellcode(func, context):
    all_shellcodes.append((func, func.func_name, context))
