FROM pwntools/pwntools:base

USER root
RUN python3 -m pip uninstall --break-system-packages -q -y pwntools && python3 -m pip install --no-cache-dir --break-system-packages --upgrade git+https://github.com/Gallopsled/pwntools@stable
RUN PWNLIB_NOTERM=1 pwn update
USER pwntools
