FROM pwntools/pwntools:stable

USER root
RUN pip install --upgrade git+https://github.com/Gallopsled/pwntools@beta
RUN PWNLIB_NOTERM=1 pwn update
USER pwntools
