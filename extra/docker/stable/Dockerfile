FROM pwntools/pwntools:base

USER root
RUN pip install --upgrade git+https://github.com/Gallopsled/pwntools@stable
RUN PWNLIB_NOTERM=1 pwn update
USER pwntools
