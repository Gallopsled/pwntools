FROM pwntools/pwntools:base

USER root
RUN python2.7 -m pip install --no-cache-dir --upgrade git+https://github.com/Gallopsled/pwntools@stable \
    && python3 -m pip install --no-cache-dir --force-reinstall --upgrade git+https://github.com/Gallopsled/pwntools@stable
RUN PWNLIB_NOTERM=1 pwn update
USER pwntools
