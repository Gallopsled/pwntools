<% from pwnlib.shellcraft import amd64 %>
<%docstring>Find the base address of ntdll.dll in memory.

Args:
    dest (str): The register to load the ntdll.dll base address into.
</%docstring>
<%page args="dest='rax'"/>
## The loaded list of modules always starts with:
## 1. the executable itself
## 2. ntdll.dll
## 3. kernel32.dll
    ${amd64.windows.peb(dest)}
    mov ${dest}, [${dest} + 0x18] /* PEB->Ldr */
    mov rsi, [${dest} + 0x20] /* PEB->Ldr.InMemOrder LIST_ENTRY */
    lodsq
    mov ${dest}, [rax + 0x20] /* LDR_DATA_TABLE_ENTRY->DllBase */
