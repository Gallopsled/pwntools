<%page args="index, register"/>
<%docstring>
Loads a stack-based argument into a register.

Assumes that the 'prolog' code was used to save EBP.

Arguments:
    index(int):
        Zero-based argument index.
    register(str):
        Register name.
</%docstring>
    mov ${register}, [ebp+${4*(index+2)}]
