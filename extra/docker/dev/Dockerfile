FROM pwntools/pwntools:stable

USER root
RUN python3 -m pip install --force-reinstall --upgrade git+https://github.com/Gallopsled/pwntools@dev
RUN PWNLIB_NOTERM=1 pwn update
USER pwntools
