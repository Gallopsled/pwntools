<%
  from pwnlib.log import getLogger
  from pwnlib.shellcraft import pretty
  from pwnlib.shellcraft.registers import get_register, is_register
  log = getLogger('pwnlib.shellcraft.amd64.teb')
%>
<%page args="dest='rax', offset=0"/>
<%docstring>Loads the Thread Environment Block (TEB) into the target register.

Args:
    dest (str): The register to load the TEB into.
    offset (int): The offset from the TEB to load.
</%docstring>
<%
if not is_register(dest):
    log.error('%r is not a register' % dest)

dest = get_register(dest)
%>
    xor esi, esi
    mov ${dest}, qword ptr gs:[rsi+${pretty(offset)}]
