<%docstring>Go from ARM to THUMB mode.</%docstring>
    .arm
    add r3, pc, #1
    bx  r3
    .thumb
