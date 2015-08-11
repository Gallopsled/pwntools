<% from pwnlib.shellcraft import i386 %>
<%docstring>Retrieves the value of EIP, stores it in the desired register.

Args:
    return_value: Value to return
</%docstring>
<%page args="register = 'ecx'"/>

    call INC_EBX
.equ INC_EBX, $-1
    ret
    pop ${register}
