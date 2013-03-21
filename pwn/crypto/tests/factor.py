from sys import stdout
from pwn.crypto.util import factor, fermat_factor, factor_pollard_rho, TimeoutError

# Fermat numbers to try factoring
# Fun fact: F8 took 2 hours when Pollard first ran his algorithm
F5 = 4294967297
F6 = 18446744073709551617
F7 = 340282366920938463463374607431768211457
F8 = 115792089237316195423570985008687907853269984665640564039457584007913129639937

numbers = [F5, F6, F7, F8]
algos = [("Fermat: ", fermat_factor), ("Pollard (Brent): ", factor_pollard_rho)]

for n in numbers:
    print "Factoring {0}".format(n)

    for (desc,alg) in algos:
        stdout.write(desc)
        stdout.flush()
        try: print alg(n)
        except TimeoutError: print "Time limit reached."

    print ""
