FROM pwntools/pwntools:stable

USER root
RUN python3 -m pip install --no-cache-dir --force-reinstall --upgrade git+https://github.com/Gallopsled/pwntools@beta
RUN PWNLIB_NOTERM=1 pwn update
USER pwntools
